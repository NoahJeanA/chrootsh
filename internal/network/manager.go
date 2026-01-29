package network

import (
	"fmt"
	"os/exec"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"

	"ssh-user-manager/config"
	"ssh-user-manager/internal/auth"
)

type Manager struct {
	mu            sync.RWMutex
	store         *auth.Store
	bridgeSetup   bool
	allocatedIPs  map[string]bool  // Track allocated IPs
	nextIP        int              // Sequential IP counter
}

func NewManager(store *auth.Store) *Manager {
	return &Manager{
		store:        store,
		allocatedIPs: make(map[string]bool),
		nextIP:       2, // Start from 10.42.0.2 (10.42.0.1 is gateway)
	}
}

func (m *Manager) SetupBridge() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.bridgeSetup {
		return nil
	}

	// Check if bridge exists
	cmd := exec.Command("ip", "link", "show", config.BridgeName)
	if err := cmd.Run(); err == nil {
		log.Info().Str("bridge", config.BridgeName).Msg("Bridge already exists")
		m.bridgeSetup = true
		return nil
	}

	log.Info().
		Str("bridge", config.BridgeName).
		Str("network", config.NetworkCIDR).
		Msg("Creating bridge network")

	cmds := [][]string{
		{"ip", "link", "add", "name", config.BridgeName, "type", "bridge"},
		{"ip", "addr", "add", config.GatewayIP + "/24", "dev", config.BridgeName},
		{"ip", "link", "set", config.BridgeName, "up"},
	}

	for _, cmdArgs := range cmds {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to run %v: %w, output: %s", cmdArgs, err, output)
		}
	}

	// Setup NAT for internet access
	primaryIface := "eth0"
	if output, err := exec.Command("ip", "route", "show", "default").Output(); err == nil {
		fields := strings.Fields(string(output))
		for i, field := range fields {
			if field == "dev" && i+1 < len(fields) {
				primaryIface = fields[i+1]
				break
			}
		}
	}

	natCmds := [][]string{
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", config.NetworkCIDR, "-o", primaryIface, "-j", "MASQUERADE"},
		{"iptables", "-A", "FORWARD", "-i", config.BridgeName, "-o", primaryIface, "-j", "ACCEPT"},
		{"iptables", "-A", "FORWARD", "-o", config.BridgeName, "-i", primaryIface, "-j", "ACCEPT"},
		// Allow forwarding between ssh-bridge and all other interfaces (for K8s API access)
		{"iptables", "-A", "FORWARD", "-i", config.BridgeName, "-j", "ACCEPT"},
		{"iptables", "-A", "FORWARD", "-o", config.BridgeName, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"},
	}

	for _, cmdArgs := range natCmds {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			log.Warn().
				Err(err).
				Str("output", string(output)).
				Strs("command", cmdArgs).
				Msg("NAT setup warning")
		}
	}

	log.Info().
		Str("gateway", config.GatewayIP).
		Str("nat_interface", primaryIface).
		Msg("Bridge network created successfully")
	m.bridgeSetup = true
	return nil
}

func (m *Manager) SetupNamespace(user *auth.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if namespace already exists
	if user.IP != "" && user.VethName != "" {
		cmd := exec.Command("ip", "netns", "list")
		if output, err := cmd.Output(); err == nil {
			netnsName := fmt.Sprintf("ns-%d", user.UID)
			if strings.Contains(string(output), netnsName) {
				log.Debug().Str("namespace", netnsName).Msg("Network namespace already exists")
				return nil
			}
		}
	}

	// Allocate IP (already have mutex lock from function)
	ip, err := m.allocateIP()
	if err != nil {
		return fmt.Errorf("failed to allocate IP: %w", err)
	}
	
	netnsName := fmt.Sprintf("ns-%d", user.UID)
	vethHost := fmt.Sprintf("veth-%d", user.UID)
	vethGuest := fmt.Sprintf("veth-g-%d", user.UID)

	log.Info().
		Str("username", user.Username).
		Str("ip", ip).
		Str("namespace", netnsName).
		Str("veth", vethHost).
		Msg("Creating network for user")

	// Create network namespace
	cmd := exec.Command("ip", "netns", "add", netnsName)
	if output, err := cmd.CombinedOutput(); err != nil {
		m.releaseIP(ip)
		return fmt.Errorf("failed to create netns: %w, output: %s", err, output)
	}

	// Create veth pair
	cmd = exec.Command("ip", "link", "add", vethHost, "type", "veth", "peer", "name", vethGuest)
	if output, err := cmd.CombinedOutput(); err != nil {
		exec.Command("ip", "netns", "del", netnsName).Run()
		m.releaseIP(ip)
		return fmt.Errorf("failed to create veth: %w, output: %s", err, output)
	}

	// Move guest veth to namespace
	cmd = exec.Command("ip", "link", "set", vethGuest, "netns", netnsName)
	if output, err := cmd.CombinedOutput(); err != nil {
		exec.Command("ip", "link", "del", vethHost).Run()
		exec.Command("ip", "netns", "del", netnsName).Run()
		m.releaseIP(ip)
		return fmt.Errorf("failed to move veth to netns: %w, output: %s", err, output)
	}

	// Rename guest veth to eth0 in namespace
	cmd = exec.Command("ip", "netns", "exec", netnsName, "ip", "link", "set", vethGuest, "name", "eth0")
	if output, err := cmd.CombinedOutput(); err != nil {
		m.releaseIP(ip)
		return fmt.Errorf("failed to rename veth: %w, output: %s", err, output)
	}

	// Attach host veth to bridge
	cmd = exec.Command("ip", "link", "set", vethHost, "master", config.BridgeName)
	if output, err := cmd.CombinedOutput(); err != nil {
		m.releaseIP(ip)
		return fmt.Errorf("failed to attach veth to bridge: %w, output: %s", err, output)
	}

	// Bring up host veth
	cmd = exec.Command("ip", "link", "set", vethHost, "up")
	if output, err := cmd.CombinedOutput(); err != nil {
		m.releaseIP(ip)
		return fmt.Errorf("failed to bring up host veth: %w, output: %s", err, output)
	}

	// Configure IP in namespace
	cmds := [][]string{
		{"ip", "netns", "exec", netnsName, "ip", "addr", "add", ip + "/24", "dev", "eth0"},
		{"ip", "netns", "exec", netnsName, "ip", "link", "set", "eth0", "up"},
		{"ip", "netns", "exec", netnsName, "ip", "link", "set", "lo", "up"},
		{"ip", "netns", "exec", netnsName, "ip", "route", "add", "default", "via", config.GatewayIP},
	}

	for _, cmdArgs := range cmds {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			m.releaseIP(ip)
			return fmt.Errorf("failed to configure namespace: %w, output: %s", err, output)
		}
	}

	// Update user
	user.IP = ip
	user.VethName = vethHost

	return m.store.UpdateUser(user)
}

func (m *Manager) CleanupNamespace(user *auth.User) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if user.VethName == "" {
		return nil
	}

	netnsName := fmt.Sprintf("ns-%d", user.UID)

	// Delete namespace (automatically deletes guest veth)
	exec.Command("ip", "netns", "del", netnsName).Run()

	// Delete host veth
	exec.Command("ip", "link", "del", user.VethName).Run()

	// Release IP
	if user.IP != "" {
		m.releaseIP(user.IP)
	}

	log.Info().Str("username", user.Username).Str("ip", user.IP).Msg("Cleaned up network")
	return nil
}

// allocateIP finds and returns the next available IP address
// Must be called with m.mu lock held
func (m *Manager) allocateIP() (string, error) {
	// Try sequential allocation starting from nextIP
	for attempts := 0; attempts < 253; attempts++ {
		if m.nextIP > 254 {
			m.nextIP = 2 // Wrap around
		}
		
		ip := fmt.Sprintf("10.42.0.%d", m.nextIP)
		m.nextIP++
		
		// Check if IP is already allocated
		if !m.allocatedIPs[ip] {
			m.allocatedIPs[ip] = true
			log.Debug().Str("ip", ip).Msg("Allocated IP address")
			return ip, nil
		}
	}
	
	return "", fmt.Errorf("no available IP addresses (all 253 addresses in use)")
}

// releaseIP marks an IP address as available for reuse
// Must be called with m.mu lock held
func (m *Manager) releaseIP(ip string) {
	if m.allocatedIPs[ip] {
		delete(m.allocatedIPs, ip)
		log.Debug().Str("ip", ip).Msg("Released IP address")
	}
}
