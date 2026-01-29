package chroot

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"

	"ssh-user-manager/config"
	"ssh-user-manager/internal/auth"
)

type Manager struct {
	mu    sync.RWMutex
	store *auth.Store
}

func NewManager(store *auth.Store) *Manager {
	return &Manager{
		store: store,
	}
}

func (m *Manager) GetOrCreateChroot(user *auth.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if chroot already exists
	if user.ChrootDir != "" {
		if _, err := os.Stat(user.ChrootDir); err == nil {
			log.Debug().
				Str("username", user.Username).
				Str("path", user.ChrootDir).
				Msg("Restoring existing chroot")
			return nil
		}
	}

	// Create new chroot
	chrootDir := fmt.Sprintf("%s/%s", config.ChrootBaseDir, user.Username)
	homeDir := "/home"

	log.Info().
		Str("username", user.Username).
		Str("path", chrootDir).
		Msg("Creating new chroot")

	if err := setupChroot(chrootDir, user.UID); err != nil {
		return fmt.Errorf("failed to setup chroot: %w", err)
	}

	if err := setupHome(chrootDir, homeDir, user.UID); err != nil {
		return fmt.Errorf("failed to setup home: %w", err)
	}

	// Update user with chroot info
	user.ChrootDir = chrootDir
	user.HomeDir = homeDir

	return m.store.UpdateUser(user)
}

func (m *Manager) DeleteChroot(username string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	user, err := m.store.GetUser(username)
	if err != nil {
		return err
	}

	if user.ChrootDir == "" {
		return nil
	}

	// Unmount /dev/pts
	exec.Command("umount", user.ChrootDir+"/dev/pts").Run()
	exec.Command("umount", user.ChrootDir+"/proc").Run()
	exec.Command("umount", user.ChrootDir+"/var/run/secrets/kubernetes.io/serviceaccount").Run()

	// Remove chroot directory
	if err := os.RemoveAll(user.ChrootDir); err != nil {
		log.Warn().
			Err(err).
			Str("path", user.ChrootDir).
			Msg("Failed to remove chroot")
	}

	return nil
}

func setupChroot(chrootDir string, uid int) error {
	// Create base directories
	dirs := []string{
		chrootDir + "/bin",
		chrootDir + "/usr/bin",
		chrootDir + "/lib",
		chrootDir + "/lib64",
		chrootDir + "/usr/lib",
		chrootDir + "/usr/share",
		chrootDir + "/usr/share/terminfo",
		chrootDir + "/etc/terminfo",
		chrootDir + "/dev",
		chrootDir + "/proc",
		chrootDir + "/tmp",
		chrootDir + "/home",
		chrootDir + "/etc",
		chrootDir + "/etc/sudoers.d",
		chrootDir + "/var",
		chrootDir + "/var/cache",
		chrootDir + "/var/cache/apk",
		chrootDir + "/var/run",
		chrootDir + "/var/run/secrets",
		chrootDir + "/var/run/secrets/kubernetes.io",
		chrootDir + "/var/run/secrets/kubernetes.io/serviceaccount",
		chrootDir + "/sbin",
		chrootDir + "/dev/pts",
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	// Copy essential binaries
	binaries := []string{
		"/bin/bash",
		"/bin/sh",
		"/bin/zsh",
		"/bin/ls",
		"/bin/cat",
		"/bin/pwd",
		"/bin/echo",
		"/bin/ps",
		"/bin/kill",
		"/bin/rm",
		"/bin/mkdir",
		"/bin/touch",
		"/bin/grep",
		"/bin/sed",
		"/bin/awk",
		"/bin/find",
		"/bin/tar",
		"/bin/gzip",
		"/bin/gunzip",
		"/bin/wget",
		"/bin/hostname",
		"/bin/uname",
		"/usr/bin/git",
		"/usr/bin/curl",
		"/usr/bin/kubectl",
		"/usr/bin/vi",
		"/usr/bin/vim",
		"/usr/bin/nano",
		"/usr/bin/less",
		"/usr/bin/more",
		"/usr/bin/head",
		"/usr/bin/tail",
		"/usr/bin/wc",
		"/usr/bin/sort",
		"/usr/bin/uniq",
		"/usr/bin/diff",
		"/usr/bin/patch",
		"/usr/bin/env",
		"/usr/bin/clear",
		"/usr/bin/tput",
		"/usr/bin/fzf",
		"/usr/bin/dirname",
		"/usr/bin/basename",
		"/usr/bin/fastfetch",
		"/usr/bin/eza",
		"/usr/bin/uptime",
		"/usr/bin/cut",
		"/usr/bin/tr",
		"/sbin/apk",
		"/usr/bin/sudo",
		"/sbin/ip",
		"/bin/ping",
		"/usr/bin/nc",
		"/usr/bin/netstat",
		"/usr/bin/arp-scan",
	}

	for _, binary := range binaries {
		if _, err := os.Stat(binary); err == nil {
			copyBinary(binary, chrootDir)
		}
	}

	// Set capabilities for network tools
	arpscanPath := chrootDir + "/usr/bin/arp-scan"
	if _, err := os.Stat(arpscanPath); err == nil {
		exec.Command("setcap", "cap_net_raw+ep", arpscanPath).Run()
	}

	pingPath := chrootDir + "/bin/ping"
	if _, err := os.Stat(pingPath); err == nil {
		exec.Command("setcap", "cap_net_raw+ep", pingPath).Run()
	}

	// Setup BusyBox symlinks
	if _, err := os.Stat("/bin/busybox"); err == nil {
		busyboxPath := chrootDir + "/bin/busybox"
		os.MkdirAll(chrootDir+"/bin", 0755)
		cmd := exec.Command("cp", "/bin/busybox", busyboxPath)
		output, err := cmd.CombinedOutput()
		if err != nil {
			log.Warn().
				Err(err).
				Str("output", string(output)).
				Msg("Failed to copy busybox")
		}
		exec.Command("chmod", "+x", busyboxPath).Run()

		busyboxCommands := []string{
			"mv", "cp", "rm", "mkdir", "touch", "cat", "ls", "pwd", "echo",
			"grep", "sed", "awk", "find", "tar", "gzip", "gunzip", "wget",
			"head", "tail", "wc", "sort", "uniq", "less", "more", "clear",
			"env", "whoami", "id", "hostname", "uname", "which", "cut", "tr",
			"sleep", "basename", "dirname", "date", "test",
		}
		for _, cmd := range busyboxCommands {
			linkPath := chrootDir + "/bin/" + cmd
			os.Remove(linkPath)
			os.Symlink("/bin/busybox", linkPath)
		}
	}

	// Copy terminfo database for terminal capabilities
	terminfoDirs := []string{
		"/usr/share/terminfo",
		"/lib/terminfo",
		"/etc/terminfo",
	}
	
	for _, src := range terminfoDirs {
		if _, err := os.Stat(src); err == nil {
			dest := chrootDir + src
			os.MkdirAll(dest, 0755)
			
			cmd := exec.Command("cp", "-r", src+"/.", dest)
			if err := cmd.Run(); err != nil {
				log.Warn().Err(err).Str("path", src).Msg("Failed to copy terminfo")
			} else {
				log.Debug().Str("src", src).Str("dest", dest).Msg("Copied terminfo database")
				break // Only need one successful copy
			}
		}
	}

	// Copy FZF files
	if _, err := os.Stat("/usr/share/fzf"); err == nil {
		fzfShareDir := chrootDir + "/usr/share/fzf"
		os.MkdirAll(fzfShareDir, 0755)
		exec.Command("cp", "-r", "/usr/share/fzf/.", fzfShareDir).Run()
	}

	// Copy bash completion
	if _, err := os.Stat("/usr/share/bash-completion"); err == nil {
		completionDir := chrootDir + "/usr/share/bash-completion"
		os.MkdirAll(completionDir, 0755)
		exec.Command("cp", "-r", "/usr/share/bash-completion/.", completionDir).Run()
	}

	// Setup APK
	os.MkdirAll(chrootDir+"/etc/apk", 0755)
	os.MkdirAll(chrootDir+"/var/cache/apk", 0755)
	os.MkdirAll(chrootDir+"/lib/apk/db", 0755)

	if _, err := os.Stat("/etc/apk/repositories"); err == nil {
		exec.Command("cp", "/etc/apk/repositories", chrootDir+"/etc/apk/repositories").Run()
	}

	if _, err := os.Stat("/etc/apk/keys"); err == nil {
		os.MkdirAll(chrootDir+"/etc/apk/keys", 0755)
		exec.Command("cp", "-r", "/etc/apk/keys/.", chrootDir+"/etc/apk/keys/").Run()
	}

	os.WriteFile(chrootDir+"/etc/apk/world", []byte(""), 0644)

	// Setup sudoers
	sudoersDir := chrootDir + "/etc/sudoers.d"
	os.MkdirAll(sudoersDir, 0755)
	sudoersContent := fmt.Sprintf("Defaults !requiretty\n%s ALL=(ALL) NOPASSWD: /sbin/apk\n", 
		fmt.Sprintf("user%d", uid))
	os.WriteFile(sudoersDir+"/apk", []byte(sudoersContent), 0440)

	// Create devices
	devices := map[string]struct{ major, minor int }{
		"null":    {1, 3},
		"zero":    {1, 5},
		"random":  {1, 8},
		"urandom": {1, 9},
		"tty":     {5, 0},
		"ptmx":    {5, 2},
	}

	for name, dev := range devices {
		devPath := chrootDir + "/dev/" + name
		cmd := exec.Command("mknod", devPath, "c", strconv.Itoa(dev.major), strconv.Itoa(dev.minor))
		cmd.Run()
		os.Chmod(devPath, 0666)
	}

	os.Chmod(chrootDir+"/tmp", 0777)

	// Copy sudo lib
	if _, err := os.Stat("/usr/lib/sudo"); err == nil {
		sudoLibDir := chrootDir + "/usr/lib/sudo"
		os.MkdirAll(sudoLibDir, 0755)
		exec.Command("cp", "-r", "/usr/lib/sudo/.", sudoLibDir).Run()
	}

	// Mount /dev/pts
	exec.Command("mount", "-t", "devpts", "devpts", chrootDir+"/dev/pts", "-o", "newinstance,ptmxmode=0666").Run()

	// Create /etc/passwd and /etc/group
	passwdContent := fmt.Sprintf("root:x:0:0:root:/root:/bin/sh\nuser%d:x:%d:%d:User:/home:/bin/bash\n", uid, uid, uid)
	groupContent := fmt.Sprintf("root:x:0:\nuser%d:x:%d:\n", uid, uid)

	os.WriteFile(chrootDir+"/etc/passwd", []byte(passwdContent), 0644)
	os.WriteFile(chrootDir+"/etc/group", []byte(groupContent), 0644)

	// Setup DNS - copy from host or use defaults
	hostResolvConf := "/etc/resolv.conf"
	if resolvData, err := os.ReadFile(hostResolvConf); err == nil {
		// Use host's DNS configuration (includes cluster DNS)
		os.WriteFile(chrootDir+"/etc/resolv.conf", resolvData, 0644)
	} else {
		// Fallback to public DNS
		resolvConf := `nameserver 8.8.8.8
nameserver 8.8.4.4
nameserver 1.1.1.1
nameserver 1.0.0.1
options ndots:0
`
		os.WriteFile(chrootDir+"/etc/resolv.conf", []byte(resolvConf), 0644)
	}

	// Copy CA certificates
	if _, err := os.Stat("/etc/ssl"); err == nil {
		os.MkdirAll(chrootDir+"/etc/ssl", 0755)
		exec.Command("cp", "-rL", "/etc/ssl/.", chrootDir+"/etc/ssl/").Run()
	}

	// Setup sudoers main file
	sudoersMain := `Defaults env_reset
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
root ALL=(ALL:ALL) ALL
@includedir /etc/sudoers.d
`
	os.WriteFile(chrootDir+"/etc/sudoers", []byte(sudoersMain), 0440)

	// Copy zsh modules
	if _, err := os.Stat("/usr/lib/zsh"); err == nil {
		zshLibDir := chrootDir + "/usr/lib/zsh"
		os.MkdirAll(zshLibDir, 0755)
		exec.Command("cp", "-r", "/usr/lib/zsh/.", zshLibDir).Run()
	}

	// Copy zsh functions
	if _, err := os.Stat("/usr/share/zsh"); err == nil {
		zshShareDir := chrootDir + "/usr/share/zsh"
		os.MkdirAll(zshShareDir, 0755)
		exec.Command("cp", "-r", "/usr/share/zsh/.", zshShareDir).Run()
	}

	// Mount ServiceAccount credentials for Kubernetes API access
	serviceAccountDir := "/var/run/secrets/kubernetes.io/serviceaccount"
	if _, err := os.Stat(serviceAccountDir); err == nil {
		chrootSADir := chrootDir + serviceAccountDir
		os.MkdirAll(chrootSADir, 0755)
		
		// Bind mount the serviceaccount directory into chroot
		cmd := exec.Command("mount", "--bind", serviceAccountDir, chrootSADir)
		if err := cmd.Run(); err != nil {
			log.Warn().
				Err(err).
				Str("path", serviceAccountDir).
				Msg("Failed to mount ServiceAccount credentials (not in K8s cluster?)")
		} else {
			log.Debug().
				Str("source", serviceAccountDir).
				Str("target", chrootSADir).
				Msg("Mounted ServiceAccount credentials into chroot")
		}
	}

	// Setup kubeconfig for kubectl
	// Use gateway IP with port 6443 (forwarded by network manager to K8s API)
	kubernetesHost := fmt.Sprintf("https://%s:6443", config.GatewayIP)
	
	kubeconfigContent := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
    server: %s
  name: default-cluster
contexts:
- context:
    cluster: default-cluster
    namespace: jail
    user: default-user
  name: default-context
current-context: default-context
users:
- name: default-user
  user:
    tokenFile: /var/run/secrets/kubernetes.io/serviceaccount/token
`, kubernetesHost)
	os.WriteFile(chrootDir+"/etc/kubeconfig", []byte(kubeconfigContent), 0644)

return nil
}

func copyBinary(srcPath, chrootDir string) error {
	dstPath := chrootDir + srcPath

	// Create destination directory
	dstDir := dstPath[:strings.LastIndex(dstPath, "/")]
	os.MkdirAll(dstDir, 0755)

	// Copy binary
	cmd := exec.Command("cp", srcPath, dstPath)
	if err := cmd.Run(); err != nil {
		return err
	}

	// Copy dependent libraries
	cmd = exec.Command("ldd", srcPath)
	output, err := cmd.Output()
	if err != nil {
		return nil // No error if ldd fails
	}

	// Parse ldd output
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		for i, field := range fields {
			if strings.HasPrefix(field, "/") && (strings.Contains(field, ".so") || strings.Contains(field, "ld-linux")) {
				if i+1 < len(fields) && fields[i+1] == "=>" && i+2 < len(fields) {
					libPath := fields[i+2]
					copyLib(libPath, chrootDir)
				} else {
					copyLib(field, chrootDir)
				}
			}
		}
	}

	return nil
}


func copyLib(libPath, chrootDir string) error {
libPath = strings.Trim(libPath, "()")
if _, err := os.Stat(libPath); err != nil {
return nil
}

dstPath := chrootDir + libPath
dstDir := dstPath[:strings.LastIndex(dstPath, "/")]

os.MkdirAll(dstDir, 0755)

cmd := exec.Command("cp", "-L", libPath, dstPath)
return cmd.Run()
}
