#!/bin/bash
# build_karos_deb.sh
set -e

PKG_NAME="karos"
PKG_VERSION="1.0-1"
BUILD_DIR="/tmp/${PKG_NAME}_build"

echo ">> Membersihkan build lama..."
rm -rf "$BUILD_DIR"

echo ">> Membuat struktur direktori..."
mkdir -p "$BUILD_DIR"/{DEBIAN,etc/karos,var/lib/karos,usr/bin,lib/systemd/system,etc/init.d}

# --- Control file ---
cat > "$BUILD_DIR/DEBIAN/control" <<EOF
Package: $PKG_NAME
Version: $PKG_VERSION
Section: net
Priority: optional
Architecture: all
Depends: python3-flask, iproute2, hostapd, dnsmasq, ppp, pptpd, mariadb-server, python3-cryptography
Maintainer: Karos Dev <dev@karos.local>
Description: Karos - MikroTik style router OS on Debian
 RouterOS-like system with web UI, DHCP, VLAN, Hotspot, PPPoE/PPTP, Firewall.
EOF

# --- Postinst (setup wizard + dependencies) ---
cat > "$BUILD_DIR/DEBIAN/postinst" <<'EOF'
#!/bin/bash
set -e

# Install any missing packages
apt-get update
apt-get install -y python3-flask iproute2 hostapd dnsmasq ppp pptpd mariadb-server python3-cryptography

# First-run setup
if [ ! -f /etc/karos/.initialized ]; then
    echo "=== Karos Initial Setup ==="
    
    # List interfaces
    echo "Available interfaces:"
    ip link show | awk -F: '$0 !~ "lo|vir|docker|^[^0-9]"{print $2}'
    
    read -p "Choose WAN interface: " WAN_IF
    read -p "Choose LAN interface: " LAN_IF
    read -s -p "Set root password: " NEWPASS
    echo
    echo "root:$NEWPASS" | chpasswd

    # Default configs
    echo "WAN=$WAN_IF" > /etc/karos/network.conf
    echo "LAN=$LAN_IF" >> /etc/karos/network.conf
    echo ".initialized" > /etc/karos/.initialized

    echo "Initial setup complete!"
fi

# Service handling
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable karos
    systemctl restart karos || true
else
    update-rc.d karos defaults
    service karos restart || true
fi

echo ">> Karos installed. Access WebUI at http://<LAN_IP>:8080"
EOF
chmod 755 "$BUILD_DIR/DEBIAN/postinst"

# --- Systemd service ---
cat > "$BUILD_DIR/lib/systemd/system/karos.service" <<EOF
[Unit]
Description=Karos WebUI
After=network.target
[Service]
ExecStart=/usr/bin/karos-webui
Restart=always
User=root
[Install]
WantedBy=multi-user.target
EOF

# --- SysVinit fallback ---
cat > "$BUILD_DIR/etc/init.d/karos" <<'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides: karos
# Required-Start: $network
# Required-Stop: $network
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: Karos WebUI
### END INIT INFO

case "$1" in
    start) /usr/bin/karos-webui & ;;
    stop) pkill -f karos-webui ;;
    restart) pkill -f karos-webui; /usr/bin/karos-webui & ;;
    *) echo "Usage: $0 {start|stop|restart}" ; exit 1 ;;
esac
exit 0
EOF
chmod 755 "$BUILD_DIR/etc/init.d/karos"

# --- WebUI starter ---
cat > "$BUILD_DIR/usr/bin/karos-webui" <<'EOF'
#!/usr/bin/env python3
from flask import Flask, render_template_string
app = Flask(__name__)

TEMPLATE = '''
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Karos WebUI</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body class="bg-dark text-light">
<div class="container py-4">
  <h1>Karos WebUI</h1>
  <p>MikroTik style management interface.</p>
  <ul>
    <li>WAN/LAN configuration</li>
    <li>DHCP, VLAN, Hotspot, Firewall</li>
    <li>PPP/PPTP server/client</li>
    <li>RADIUS</li>
  </ul>
</div>
</body>
</html>
'''

@app.route("/")
def index():
    return render_template_string(TEMPLATE)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
EOF
chmod 755 "$BUILD_DIR/usr/bin/karos-webui"

# --- Build .deb ---
echo ">> Building .deb package..."
dpkg-deb --build "$BUILD_DIR"
echo ">> Done! File: ${BUILD_DIR}.deb"
