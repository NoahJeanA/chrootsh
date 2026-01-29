# SSH User Manager

Ein Go-basierter SSH-Server, der für jede eingehende SSH-Verbindung automatisch einen temporären Linux-User erstellt und nach Session-Ende wieder löscht.

## Features

- SSH-Server auf Port 2222  
- **Vollständige chroot-Isolation** - Jeder User sieht nur sein eigenes Dateisystem
- Automatische User-Erstellung bei SSH-Verbindung
- Jeder User erhält ein isoliertes chroot-Jail mit eigenem Home-Verzeichnis
- Automatisches Löschen des Users und chroot nach Session-Ende
- SSH-Key-Authentifizierung
- Läuft in Docker-Container

## Voraussetzungen

- Docker
- Go 1.21+ (für lokale Entwicklung)

## Installation & Start

### Mit Docker

```bash
cd ssh-user-manager

# SSH Key für Join-User generieren (falls noch nicht vorhanden)
# ssh-keygen -t ed25519 -f join_key -N "" -C "join@ssh-user-manager"

# Dependencies herunterladen
go mod tidy

# Docker Image bauen
docker build -t ssh-user-manager .

# Container starten (privilegiert für User-Verwaltung)
docker run -d -p 2222:2222 --privileged --name ssh-server ssh-user-manager
```

### Lokal (Entwicklung)

```bash
# Dependencies installieren
go mod tidy

# Als Root ausführen (benötigt für useradd/userdel)
sudo go run main.go
```

## Verwendung

Verbinde dich mit dem SSH-Server als User "join" mit dem Private Key:

```bash
ssh -p 2222 -i join_key join@localhost
```

**Wichtig:** Der Private Key `join_key` muss auf dem Client verfügbar sein!

Bei jeder Verbindung wird automatisch:
1. Ein neuer User mit Namen `tmp<UID>` erstellt
2. Ein chroot-Jail unter `/tmp/chroots/tmp<UID>` angelegt
3. Notwendige Binaries (bash, ls, cat, etc.) und Libraries ins chroot kopiert
4. Ein isoliertes Home-Verzeichnis im chroot erstellt
5. Du wirst als dieser User im chroot eingeloggt (siehst nur dein eigenes Dateisystem!)
6. Nach dem Logout werden User und chroot automatisch gelöscht

## Konfiguration

- **Port**: Standardmäßig Port 2222 (änderbar in `main.go`)
- **Host Key**: Verwendet System SSH Host Keys aus `/etc/ssh/`
- **UID Range**: 10000-60000
- **Chroot Binaries**: bash, sh, ls, cat, pwd, echo, touch, mkdir, rm, cp, mv, vi, nano
- **Isolation**: Komplette chroot-Jail - User sieht nur sein eigenes Dateisystem

## Sicherheitshinweise

⚠️ **Wichtig**: Dieses Programm benötigt Root-Rechte (oder `--privileged` in Docker) um User erstellen/löschen zu können.

- Nur in isolierten Umgebungen verwenden (Docker empfohlen)
- Keine Authentifizierung im Beispiel-Code
- Für Produktion: Authentifizierung hinzufügen

## Logs

Container-Logs anzeigen:
```bash
docker logs -f ssh-server
```

## Troubleshooting

**Container stoppt sofort:**
```bash
docker logs ssh-server
```

**Permission Denied:**
- Container muss mit `--privileged` gestartet werden
- Oder füge Capabilities hinzu: `--cap-add=SYS_ADMIN`

**SSH Verbindung schlägt fehl:**
```bash
# Prüfe ob Port offen ist
docker ps
netstat -tlnp | grep 2222
```
