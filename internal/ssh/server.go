package ssh

import (
"fmt"
"io/ioutil"
"net"

"github.com/rs/zerolog/log"
"golang.org/x/crypto/ssh"

"ssh-user-manager/config"
"ssh-user-manager/internal/auth"
"ssh-user-manager/internal/chroot"
"ssh-user-manager/internal/network"
)

type Server struct {
config      *ssh.ServerConfig
listener    net.Listener
authStore   *auth.Store
chrootMgr   *chroot.Manager
networkMgr  *network.Manager
}

func NewServer(authStore *auth.Store, chrootMgr *chroot.Manager, networkMgr *network.Manager) (*Server, error) {
// Load join authorized keys
joinKeysBytes, err := ioutil.ReadFile("/etc/ssh/authorized_keys")
if err != nil {
return nil, fmt.Errorf("failed to load join keys: %w", err)
}

joinKeys := []ssh.PublicKey{}
for len(joinKeysBytes) > 0 {
pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(joinKeysBytes)
if err != nil {
break
}
joinKeys = append(joinKeys, pubKey)
joinKeysBytes = rest
}

// Load admin authorized keys
adminKeysBytes, err := ioutil.ReadFile("/etc/ssh/admin_keys")
adminKeys := []ssh.PublicKey{}
if err == nil {
for len(adminKeysBytes) > 0 {
pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(adminKeysBytes)
if err != nil {
break
}
adminKeys = append(adminKeys, pubKey)
adminKeysBytes = rest
}
}

if len(joinKeys) == 0 {
return nil, fmt.Errorf("no join keys found")
}

log.Info().
		Int("join_keys", len(joinKeys)).
		Int("admin_keys", len(adminKeys)).
		Msg("Loaded SSH authentication keys")

// SSH server config - ONLY public key auth
sshConfig := &ssh.ServerConfig{
NoClientAuth: false,
PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
username := conn.User()

// Check if admin user
if username == "admin" {
for _, authKey := range adminKeys {
if string(key.Marshal()) == string(authKey.Marshal()) {
log.Info().
Str("username", "admin").
Str("remote_addr", conn.RemoteAddr().String()).
Msg("Admin connection accepted")
return nil, nil
}
}
return nil, fmt.Errorf("unauthorized admin key")
}

// Check if join user
if username == "join" {
for _, authKey := range joinKeys {
if string(key.Marshal()) == string(authKey.Marshal()) {
log.Info().
Str("username", "join").
Str("remote_addr", conn.RemoteAddr().String()).
Msg("Join connection accepted")
return nil, nil
}
}
return nil, fmt.Errorf("unauthorized join key")
}

return nil, fmt.Errorf("unknown user: %s", username)
},
}

// Load host key
hostKey, err := loadOrGenerateHostKey(config.HostKeyPath)
if err != nil {
return nil, fmt.Errorf("failed to load host key: %w", err)
}
sshConfig.AddHostKey(hostKey)

// Start listening
listener, err := net.Listen("tcp", "0.0.0.0:"+config.SSHPort)
if err != nil {
return nil, fmt.Errorf("failed to listen: %w", err)
}

return &Server{
config:     sshConfig,
listener:   listener,
authStore:  authStore,
chrootMgr:  chrootMgr,
networkMgr: networkMgr,
}, nil
}

func (s *Server) Start() error {
log.Info().Str("port", config.SSHPort).Msg("SSH server listening")

for {
tcpConn, err := s.listener.Accept()
if err != nil {
log.Error().Err(err).Msg("Failed to accept connection")
continue
}

go s.handleConnection(tcpConn)
}
}

func (s *Server) Close() error {
return s.listener.Close()
}

func loadOrGenerateHostKey(path string) (ssh.Signer, error) {
keyBytes, err := ioutil.ReadFile(path)
if err == nil {
return ssh.ParsePrivateKey(keyBytes)
}

for _, keyPath := range []string{
"/etc/ssh/ssh_host_ed25519_key",
"/etc/ssh/ssh_host_rsa_key",
"/etc/ssh/ssh_host_ecdsa_key",
} {
keyBytes, err := ioutil.ReadFile(keyPath)
if err == nil {
log.Info().Str("path", keyPath).Msg("Using host key")
return ssh.ParsePrivateKey(keyBytes)
}
}

return nil, fmt.Errorf("no host key found")
}
