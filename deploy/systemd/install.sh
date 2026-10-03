#!/usr/bin/env bash
# ==============================================================================
# Skybouncer Systemd Service Installer (Idempotent)
# ==============================================================================
set -euo pipefail

if [[ $EUID -ne 0 ]]; then
   echo "❌ Error: This installation script must be run as root (or via sudo)." >&2
   exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "🛡️ Installing Skybouncer system service..."

# 1. Create dedicated system user and group if not present
if ! id -u skybouncer >/dev/null 2>&1; then
    echo "  -> Creating system user 'skybouncer'..."
    useradd --system --shell /sbin/nologin --comment "Skybouncer Moderation Daemon" skybouncer
else
    echo "  -> System user 'skybouncer' already exists."
fi

# 2. Prepare state directory
echo "  -> Creating /var/lib/skybouncer..."
mkdir -p /var/lib/skybouncer
chown -R skybouncer:skybouncer /var/lib/skybouncer
chmod 0750 /var/lib/skybouncer

# 3. Prepare configuration directory
echo "  -> Creating /etc/skybouncer..."
mkdir -p /etc/skybouncer
if [[ ! -f /etc/skybouncer/skybouncer.env ]]; then
    echo "  -> Installing default /etc/skybouncer/skybouncer.env..."
    cp "${SCRIPT_DIR}/skybouncer.env.example" /etc/skybouncer/skybouncer.env
    chmod 0600 /etc/skybouncer/skybouncer.env
    chown root:skybouncer /etc/skybouncer/skybouncer.env
    echo "  ⚠️  IMPORTANT: Edit /etc/skybouncer/skybouncer.env to configure your credentials."
else
    echo "  -> Existing /etc/skybouncer/skybouncer.env preserved."
fi

# 4. Install binary if available
BINARY_PATH="${REPO_ROOT}/target/release/skybouncer"
if [[ -f "${BINARY_PATH}" ]]; then
    echo "  -> Installing binary to /usr/local/bin/skybouncer..."
    install -m 0755 "${BINARY_PATH}" /usr/local/bin/skybouncer
else
    echo "  ⚠️  Release binary not found at ${BINARY_PATH}."
    echo "     Build with: cargo build --release --bin skybouncer"
    echo "     Then copy target/release/skybouncer to /usr/local/bin/skybouncer"
fi

# 5. Install systemd unit
echo "  -> Installing systemd unit /etc/systemd/system/skybouncer.service..."
cp "${SCRIPT_DIR}/skybouncer.service" /etc/systemd/system/skybouncer.service
chmod 0644 /etc/systemd/system/skybouncer.service

# 6. Reload systemd daemon
echo "  -> Reloading systemd..."
systemctl daemon-reload

echo "✅ Skybouncer installation complete!"
echo ""
echo "Next steps:"
echo "  1. Configure your settings:  nano /etc/skybouncer/skybouncer.env"
echo "  2. Enable service at boot:   systemctl enable skybouncer"
echo "  3. Start the service:        systemctl start skybouncer"
echo "  4. Check status & logs:      systemctl status skybouncer"
echo "                               journalctl -u skybouncer -f"
