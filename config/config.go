package config

const (
	SSHPort          = "2222"
	HostKeyPath      = "/etc/ssh/ssh_host_ed25519_key"
	BridgeName       = "ssh-bridge"
	NetworkCIDR      = "10.42.0.0/24"
	GatewayIP        = "10.42.0.1"
	ChrootBaseDir    = "/tmp/chroots"
	DBPath           = "/var/lib/ssh-users/users.db"
	ActiveUsersFile  = "/tmp/ssh_active_users.txt"
	MinPasswordLen   = 6
	SessionTimeout   = 3600 // seconds
	InactiveCleanup  = 2592000 // 30 days in seconds
)
