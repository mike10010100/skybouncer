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
if ! getent group skybouncer >/dev/null 2>&1; then
    echo "  -> Creating system group 'skybouncer'..."
    groupadd --system skybouncer
fi
if ! id -u skybouncer >/dev/null 2>&1; then
    echo "  -> Creating system user 'skybouncer'..."
    useradd --system -g skybouncer --shell /sbin/nologin --comment "Skybouncer Moderation Daemon" skybouncer
else
    echo "  -> System user 'skybouncer' already exists."
fi

# 2. Prepare state directory
echo "  -> Creating /var/lib/skybouncer..."
mkdir -p /var/lib/skybouncer
chown -R skybouncer:skybouncer /var/lib/skybouncer
chmod 0750 /var/lib/skybouncer

# 3. Prepare configuration directory and install 0600 env file atomically
echo "  -> Creating /etc/skybouncer..."
mkdir -p /etc/skybouncer
chmod 0750 /etc/skybouncer
chown root:skybouncer /etc/skybouncer
if [[ ! -f /etc/skybouncer/skybouncer.env ]]; then
    echo "  -> Installing default /etc/skybouncer/skybouncer.env (mode 0600)..."
    install -m 0600 -o root -g skybouncer "${SCRIPT_DIR}/skybouncer.env.example" /etc/skybouncer/skybouncer.env

    # Auto-generate a 32-byte (64-hex) session encryption key on initial install
    GENERATED_KEY=""
    if command -v openssl >/dev/null 2>&1; then
        GENERATED_KEY="$(openssl rand -hex 32)"
    elif [[ -r /dev/urandom ]]; then
        GENERATED_KEY="$(od -An -tx1 -N32 /dev/urandom | tr -d ' \n')"
    fi
    if [[ -n "${GENERATED_KEY}" ]]; then
        sed -i "s|^SKYBOUNCER_SESSION_ENCRYPTION_KEY=.*|SKYBOUNCER_SESSION_ENCRYPTION_KEY=${GENERATED_KEY}|" /etc/skybouncer/skybouncer.env
        echo "  -> Generated random 64-hex SKYBOUNCER_SESSION_ENCRYPTION_KEY."
    fi
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
install -m 0644 "${SCRIPT_DIR}/skybouncer.service" /etc/systemd/system/skybouncer.service

# 6. Check OS CA distrust parity for October 2026 compromised eMudhra / Comodo AAA roots
#    (Rust TLS already distrusts these in-binary via rustls-webpki >= 0.103.16 & webpki-roots >= 1.0.10;
#    this parity check flags host /etc/ca-certificates.conf for OS tools such as curl.)
if [[ -f /etc/ca-certificates.conf ]]; then
    if grep -Eq '^(mozilla/emSign_ECC_Root_CA_-_G3\.crt|mozilla/Comodo_AAA_Services_root\.crt)$' /etc/ca-certificates.conf; then
        echo "  ⚠️  CA distrust parity notice: /etc/ca-certificates.conf still trusts eMudhra/Comodo AAA roots."
        echo "     To match Dockerfile OS trust-store hardening for curl/system tools, run:"
        echo "       sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' /etc/ca-certificates.conf && update-ca-certificates"
    fi
fi

# 7. Reload systemd daemon
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
