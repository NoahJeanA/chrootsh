package ssh

import (
"fmt"
"io"
"math/rand"
"net"
"os"
"os/exec"

"github.com/creack/pty"
"github.com/rs/zerolog/log"
"golang.org/x/crypto/ssh"

"ssh-user-manager/config"
"ssh-user-manager/internal/auth"
)

func (s *Server) handleConnection(tcpConn net.Conn) {
defer tcpConn.Close()

sshConn, chans, reqs, err := ssh.NewServerConn(tcpConn, s.config)
log.Debug().Str("remote_addr", tcpConn.RemoteAddr().String()).Msg("Starting SSH handshake")
if err != nil {
log.Warn().Err(err).Str("remote_addr", tcpConn.RemoteAddr().String()).Msg("Failed to handshake")
return
}
defer sshConn.Close()

go ssh.DiscardRequests(reqs)
log.Info().
Str("username", sshConn.User()).
Str("remote_addr", tcpConn.RemoteAddr().String()).
Msg("SSH handshake successful")

for newChannel := range chans {
log.Debug().
Str("channel_type", newChannel.ChannelType()).
Msg("New channel received")
if newChannel.ChannelType() != "session" {
newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
continue
}

channel, requests, err := newChannel.Accept()
if err != nil {
log.Error().Err(err).Msg("Failed to accept channel")
continue
}

go s.handleChannel(channel, requests, sshConn)
}
}

func (s *Server) handleChannel(channel ssh.Channel, requests <-chan *ssh.Request, sshConn *ssh.ServerConn) {
defer channel.Close()


	// Check if admin user
	if sshConn.User() == "admin" {
		s.handleAdminSession(channel, requests)
		return
	}

// Create temporary user automatically
uid := rand.Intn(50000) + 10000
username := fmt.Sprintf("tmp%d", uid)

user := &auth.User{
Username:  username,
UID:       uid,
ChrootDir: fmt.Sprintf("/tmp/chroots/%s", username),
IP:        fmt.Sprintf("10.42.0.%d", (uid%250)+2),
}

log.Info().
Str("username", user.Username).
Int("uid", user.UID).
Str("ip", user.IP).
Msg("Creating temporary user")

// Setup chroot
if err := s.chrootMgr.GetOrCreateChroot(user); err != nil {
log.Error().Err(err).Str("username", user.Username).Msg("Failed to setup chroot")
channel.Write([]byte("Failed to setup environment\r\n"))
return
}

// Setup network
if err := s.networkMgr.SetupNamespace(user); err != nil {
log.Error().Err(err).Str("username", user.Username).Msg("Failed to setup network")
channel.Write([]byte("Failed to setup network\r\n"))
return
}

updateActiveUsers(user)
defer func() {
removeActiveUser(user)
// Cleanup temporary user
// Chroot cleanup done manually
s.networkMgr.CleanupNamespace(user)
exec.Command("umount", user.ChrootDir+"/dev/pts").Run()
		exec.Command("umount", user.ChrootDir+"/proc").Run()
		os.RemoveAll(user.ChrootDir)
log.Info().Str("username", user.Username).Msg("Cleaned up temporary user")
}()

// Write network info
networkInfo := fmt.Sprintf(`SSH_USER_IP="%s"
SSH_BRIDGE_GW="%s"
export SSH_USER_IP SSH_BRIDGE_GW
`, user.IP, config.GatewayIP)
os.WriteFile(user.ChrootDir+"/home/.network_info", []byte(networkInfo), 0644)

// Start user shell
netnsName := fmt.Sprintf("ns-%d", user.UID)
cmd := exec.Command("ip", "netns", "exec", netnsName, "/usr/sbin/chroot", user.ChrootDir, "/bin/bash", "-l")
cmd.Env = []string{
"HOME=/home",
"USER=" + user.Username,
"SHELL=/bin/bash",
"TERM=xterm-256color",
"PATH=/usr/local/bin:/usr/bin:/bin:/sbin",
}

var ptmx *os.File
var termWidth, termHeight int = 80, 24

for req := range requests {
switch req.Type {
case "pty-req":
if ptmx != nil {
req.Reply(false, nil)
continue
}

termLen := req.Payload[3]
termWidth, termHeight = parseDims(req.Payload[termLen+4:])
req.Reply(true, nil)

case "window-change":
if ptmx != nil {
w, h := parseDims(req.Payload)
pty.Setsize(ptmx, &pty.Winsize{
Rows: uint16(h),
Cols: uint16(w),
})
}
if req.WantReply {
req.Reply(true, nil)
}

case "shell":
if req.WantReply {
req.Reply(true, nil)
}

var err error
ptmx, err = pty.StartWithSize(cmd, &pty.Winsize{
Rows: uint16(termHeight),
Cols: uint16(termWidth),
})
if err != nil {
log.Error().
Err(err).
Str("username", user.Username).
Msg("Failed to start PTY")
return
}

go func() {
io.Copy(channel, ptmx)
channel.Close()
}()
io.Copy(ptmx, channel)

cmd.Wait()
log.Info().Str("username", user.Username).Msg("Session ended")
return

default:
if req.WantReply {
req.Reply(false, nil)
}
}
}
log.Printf("Requests loop ended for %s", user.Username)
}

func parseDims(b []byte) (w, h int) {
if len(b) < 8 {
return 80, 24
}
w = int(b[0])<<24 | int(b[1])<<16 | int(b[2])<<8 | int(b[3])
h = int(b[4])<<24 | int(b[5])<<16 | int(b[6])<<8 | int(b[7])
if w <= 0 || h <= 0 {
w, h = 80, 24
}
return
}

func updateActiveUsers(user *auth.User) {
data, _ := os.ReadFile(config.ActiveUsersFile)
lines := []string{}
for _, line := range splitLines(string(data)) {
if line != "" && !containsUsername(line, user.Username) {
lines = append(lines, line)
}
}
lines = append(lines, fmt.Sprintf("%s %s", user.Username, user.IP))
content := ""
for _, line := range lines {
content += line + "\n"
}
os.WriteFile(config.ActiveUsersFile, []byte(content), 0644)
if user.ChrootDir != "" {
os.WriteFile(user.ChrootDir+"/tmp/active_users.txt", []byte(content), 0644)
}
}

func removeActiveUser(user *auth.User) {
data, _ := os.ReadFile(config.ActiveUsersFile)
lines := []string{}
for _, line := range splitLines(string(data)) {
if line != "" && !containsUsername(line, user.Username) {
lines = append(lines, line)
}
}
content := ""
for _, line := range lines {
content += line + "\n"
}
os.WriteFile(config.ActiveUsersFile, []byte(content), 0644)
}

func splitLines(s string) []string {
lines := []string{}
line := ""
for _, c := range s {
if c == '\n' {
if line != "" {
lines = append(lines, line)
}
line = ""
} else {
line += string(c)
}
}
if line != "" {
lines = append(lines, line)
}
return lines
}

func containsUsername(line, username string) bool {
for i := 0; i < len(line); i++ {
if line[i] == ' ' {
return line[:i] == username
}
}
return false
}
func (s *Server) handleAdminSession(channel ssh.Channel, requests <-chan *ssh.Request) {
log.Printf("Admin session started")

var ptmx *os.File
var termWidth, termHeight int = 80, 24

for req := range requests {
switch req.Type {
case "pty-req":
if ptmx != nil {
req.Reply(false, nil)
continue
}
termLen := req.Payload[3]
termWidth, termHeight = parseDims(req.Payload[termLen+4:])
req.Reply(true, nil)

case "window-change":
if ptmx != nil {
w, h := parseDims(req.Payload)
pty.Setsize(ptmx, &pty.Winsize{
Rows: uint16(h),
Cols: uint16(w),
})
}
if req.WantReply {
req.Reply(true, nil)
}

case "shell":
if req.WantReply {
req.Reply(true, nil)
}

cmd := exec.Command("/bin/sh")
cmd.Env = append(os.Environ(),
"PS1=admin@ssh-manager:~# ",
"HOME=/root",
)

var err error
ptmx, err = pty.StartWithSize(cmd, &pty.Winsize{
Rows: uint16(termHeight),
Cols: uint16(termWidth),
})
if err != nil {
log.Error().Err(err).Msg("Failed to start admin PTY")
return
}

go func() {
io.Copy(channel, ptmx)
channel.Close()
}()
go io.Copy(ptmx, channel)

cmd.Wait()
log.Info().Msg("Admin session ended")
return

default:
if req.WantReply {
req.Reply(false, nil)
}
}
}
}

