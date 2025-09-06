#!/bin/bash
# build_karos_deb.sh
# Generator .deb package for Karos (MikroTik-style router system)
set -e

PACKAGE_NAME="karos"
PACKAGE_VERSION="1.0-1"
BUILD_DIR="$PWD/${PACKAGE_NAME}_${PACKAGE_VERSION}"

# Bersihkan build dir lama
rm -rf "$BUILD_DIR"

echo ">> Membuat struktur paket"
mkdir -p "$BUILD_DIR"/{DEBIAN,usr/bin,lib/systemd/system,etc/init.d,usr/share/karos-webui/config}

# --- Control file ---
cat > "$BUILD_DIR/DEBIAN/control" <<EOF
Package: $PACKAGE_NAME
Version: $PACKAGE_VERSION
Section: net
Priority: optional
Architecture: all
Depends: python3, python3-flask, iproute2, hostapd, dnsmasq, ppp, pptpd, mariadb-server
Maintainer: KangWiFi <kangwifi@example.com>
Description: Karos - RouterOS-like system with modular network features
EOF

# --- Postinst setup wizard ---
cat > "$BUILD_DIR/DEBIAN/postinst" <<'EOF'
#!/bin/bash
set -e

CONFIG_DIR=/etc/karos
mkdir -p $CONFIG_DIR

if [ ! -f $CONFIG_DIR/.initialized ]; then
    echo "=== Karos Initial Setup ==="

    echo "Daftar interface tersedia:"
    ip -o link show | awk -F': ' '{print NR ") " $2}'

    read -p "Pilih interface untuk WAN: " WAN_IF
    read -p "Pilih interface untuk LAN: " LAN_IF

    # Password root
    echo -n "Masukkan password baru untuk root: "
    read -s NEWPASS
    echo
    echo "root:$NEWPASS" | chpasswd

    cat > $CONFIG_DIR/network.conf <<EOL
WAN=$WAN_IF
LAN=$LAN_IF
EOL

    touch $CONFIG_DIR/.initialized
    echo ">> Setup awal selesai"
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

echo ">> Karos terpasang. Akses WebUI: http://<LAN_IP>:8080"
EOF
chmod 755 "$BUILD_DIR/DEBIAN/postinst"

# --- Systemd service ---
cat > "$BUILD_DIR/lib/systemd/system/karos.service" <<EOF
[Unit]
Description=Karos RouterOS-like WebUI
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
# Short-Description: Karos RouterOS-like system
### END INIT INFO

case "$1" in
    start)
        /usr/bin/karos-webui &
        ;;
    stop)
        pkill -f karos-webui
        ;;
    restart)
        pkill -f karos-webui
        /usr/bin/karos-webui &
        ;;
    *)
        echo "Usage: /etc/init.d/karos {start|stop|restart}"
        exit 1
        ;;
esac
exit 0
EOF
chmod 755 "$BUILD_DIR/etc/init.d/karos"

# --- WebUI starter ---
cat > "$BUILD_DIR/usr/bin/karos-webui" <<'EOF'
#!/usr/bin/env python3
from flask import Flask, render_template_string
app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<title>Karos WebUI</title>
<style>
body {font-family: monospace; background:#1a1a1a; color:#fff;}
h1 {color:#00ff00;}
pre {background:#000; padding:10px;}
</style>
</head>
<body>
<h1>Karos RouterOS-like WebUI</h1>
<p>Semua fitur modular dapat dikonfigurasi di sini:</p>
<ul>
<li>DHCP Server / Client</li>
<li>Static IP</li>
<li>DNS Client</li>
<li>VLAN</li>
<li>PPPoE / PPTP</li>
<li>Firewall</li>
<li>Hotspot / Captive Portal</li>
<li>WLAN / AP</li>
<li>Routing</li>
</ul>
<pre>Semua fitur default mati. Aktifkan manual di WebUI.</pre>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML_TEMPLATE)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
EOF
chmod 755 "$BUILD_DIR/usr/bin/karos-webui"

# --- Build .deb ---
echo ">> Membuat paket .deb ..."
dpkg-deb --build "$BUILD_DIR"
echo ">> Selesai: $PWD/${BUILD_DIR}.deb"
