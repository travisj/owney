#!/bin/bash
# M6 Self-Hosting Demo: Setup → Backup → Restore

set -e

BINARY="${1:-./target/debug/mailserverd}"
DOMAIN="example.local"
DATA_DIR="/tmp/mailserver-demo"
BACKUP_DIR="$DATA_DIR/backups"

echo "=== Mailserver M6 Demo ==="
echo "Binary: $BINARY"
echo "Domain: $DOMAIN"
echo "Data: $DATA_DIR"
echo ""

# Step 1: Setup
echo "Step 1: Setup (config + keys)"
mkdir -p "$DATA_DIR"
export MAILSERVER_CONFIG="$DATA_DIR/mailserver.toml"

$BINARY config example | sed "s/example.com/$DOMAIN/g" > "$MAILSERVER_CONFIG"
echo "Config: $MAILSERVER_CONFIG"
echo ""

# Step 2: Create account & backup
echo "Step 2: Create account"
$BINARY --config "$MAILSERVER_CONFIG" admin create-account "alice@$DOMAIN"
echo ""

echo "Step 3: Create backup"
mkdir -p "$BACKUP_DIR"
BACKUP=$($BINARY --config "$MAILSERVER_CONFIG" backup create --output "$BACKUP_DIR" | grep "Backup created" | awk '{print $NF}')
echo "Backup: $BACKUP"
echo ""

# Step 4: Simulate disaster
echo "Step 4: Simulate data loss"
rm -rf "$DATA_DIR/mail.db"
echo "Deleted database"
echo ""

# Step 5: Restore
echo "Step 5: Restore from backup"
$BINARY --config "$MAILSERVER_CONFIG" backup restore "$BACKUP"
echo ""

echo "Step 6: Verify restoration"
$BINARY --config "$MAILSERVER_CONFIG" admin accounts
echo ""

echo "=== Demo Complete ==="
echo "✓ Setup wizard"
echo "✓ Account creation"
echo "✓ Backup creation"
echo "✓ Data loss recovery"
echo ""
echo "Next: Deploy to production with:"
echo "  - DNS records verified (mailserverd doctor)"
echo "  - Binary updated safely (mailserverd update)"
echo "  - Health monitoring active (background doctor daemon)"
