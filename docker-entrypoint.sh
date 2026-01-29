#!/bin/sh
set -e

echo "=== SSH User Manager - Startup ==="

KEY_DIR="/var/lib/ssh-keys"
mkdir -p "$KEY_DIR"

# Generate join key if not exists
if [ ! -f "$KEY_DIR/join_key" ]; then
    echo "Generating JOIN key..."
    ssh-keygen -t ed25519 -f "$KEY_DIR/join_key" -N "" -C "join@ssh-user-manager"
    cp "$KEY_DIR/join_key.pub" /etc/ssh/authorized_keys
    chmod 600 /etc/ssh/authorized_keys
    echo "✓ JOIN key generated"
else
    echo "✓ JOIN key exists"
    cp "$KEY_DIR/join_key.pub" /etc/ssh/authorized_keys
    chmod 600 /etc/ssh/authorized_keys
fi

# Generate admin key if not exists
if [ ! -f "$KEY_DIR/admin_key" ]; then
    echo "Generating ADMIN key..."
    ssh-keygen -t ed25519 -f "$KEY_DIR/admin_key" -N "" -C "admin@ssh-user-manager"
    cp "$KEY_DIR/admin_key.pub" /etc/ssh/admin_keys
    chmod 600 /etc/ssh/admin_keys
    echo "✓ ADMIN key generated"
else
    echo "✓ ADMIN key exists"
    cp "$KEY_DIR/admin_key.pub" /etc/ssh/admin_keys
    chmod 600 /etc/ssh/admin_keys
fi

echo ""
echo "=== SSH Keys Ready ==="
echo "To retrieve private keys:"
echo "  JOIN key:  docker exec <container> cat /var/lib/ssh-keys/join_key"
echo "  ADMIN key: docker exec <container> cat /var/lib/ssh-keys/admin_key"
echo ""
echo "Starting SSH User Manager..."

exec "$@"
