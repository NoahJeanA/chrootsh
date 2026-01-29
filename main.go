package main

import (
"os"
"os/signal"
"syscall"

"github.com/rs/zerolog"
"github.com/rs/zerolog/log"

"ssh-user-manager/config"
"ssh-user-manager/internal/auth"
"ssh-user-manager/internal/chroot"
"ssh-user-manager/internal/network"
"ssh-user-manager/internal/ssh"
)

func main() {
// Setup structured logging
zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
if os.Getenv("ENV") == "production" {
// JSON logging for production
zerolog.SetGlobalLevel(zerolog.InfoLevel)
} else {
// Pretty console logging for development
log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
zerolog.SetGlobalLevel(zerolog.DebugLevel)
}
	
// Set log level from environment
switch os.Getenv("LOG_LEVEL") {
case "debug":
zerolog.SetGlobalLevel(zerolog.DebugLevel)
case "info":
zerolog.SetGlobalLevel(zerolog.InfoLevel)
case "warn":
zerolog.SetGlobalLevel(zerolog.WarnLevel)
case "error":
zerolog.SetGlobalLevel(zerolog.ErrorLevel)
}

log.Info().Msg("Starting SSH User Manager")

// Initialize user database
authStore, err := auth.NewStore(config.DBPath)
if err != nil {
log.Fatal().Err(err).Str("db_path", config.DBPath).Msg("Failed to initialize auth store")
}
defer authStore.Close()

// Initialize network manager
networkMgr := network.NewManager(authStore)

// Setup bridge network
if err := networkMgr.SetupBridge(); err != nil {
log.Fatal().Err(err).Str("bridge", config.BridgeName).Msg("Failed to setup bridge network")
}

// Initialize chroot manager
chrootMgr := chroot.NewManager(authStore)

// Initialize SSH server
sshServer, err := ssh.NewServer(authStore, chrootMgr, networkMgr)
if err != nil {
log.Fatal().Err(err).Msg("Failed to create SSH server")
}
defer sshServer.Close()

// Handle shutdown signals
sigChan := make(chan os.Signal, 1)
signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
go func() {
<-sigChan
log.Info().Msg("Shutting down gracefully")
sshServer.Close()
authStore.Close()
os.Exit(0)
}()

// Start SSH server
log.Info().Str("port", config.SSHPort).Msg("SSH User Manager started successfully")
if err := sshServer.Start(); err != nil {
log.Fatal().Err(err).Msg("SSH server error")
}
}
