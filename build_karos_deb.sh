#!/bin/bash
# ==========================================
# Karos Full (KangWiFi RouterOS-like) .deb Generator
# ==========================================
set -e

PACKAGE_NAME="karos"
PACKAGE_VERSION="1.0-1"
BUILD_DIR="/tmp/${PACKAGE_NAME}_build"

echo ">> Membuat struktur paket Karos..."
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/DEBIAN"
mkdir -p "$BUILD_DIR/usr/bin"
mkdir -p "$BUILD_DIR/etc/karos"
mkdir -p "$BUILD_DIR/var/lib/karos"
mkdir -p "$BUILD_DIR/lib/systemd/system"
mkdir -p "$BUILD_DIR/etc/init.d"

# --- DEBIAN control ---
cat > $BUILD_DIR/DEBIAN/control <<EOF
Package: $PACKAGE_NAME
Version: $PACKAGE_VERSION
Section: admin
Priority: optional
Architecture: all
Depends: python3, python3-flask, mariadb-server, dnsmasq, hostapd, ppp, pptpd, iproute2, iptables, iputils-ping
Maintainer: Karos Team
Description: Karos RouterOS-like WebUI & system
 All features default OFF, modular, production-ready
EOF

# --- Postinst ---
cat > $BUILD_DIR/DEBIAN/postinst <<'EOF'
#!/bin/bash
set -e
echo "=== Karos Initial Setup ==="

# Create karos user
id -u karos &>/dev/null || useradd -m -s /usr/bin/karos-shell karos

# Default feature config
mkdir -p /etc/karos
mkdir -p /var/lib/karos
cat > /etc/karos/feature.conf <<EOL
[network]
wan1=eth0
wan2=eth1
wan3=eth2
lan1=eth3
lan2=eth4
lan3=eth5
lan4=eth6
lan5=eth7
lan6=eth8
lan7=eth9
lan8=eth10
lan9=eth11
lan10=eth12
lan11=eth13

[vlan]
enabled=off
[dhcp]
enabled=off
[dns]
enabled=off
[hotspot]
enabled=off
[radius]
enabled=off
[firewall]
enabled=off
[pppoe]
server=off
client=off
[pptp]
server=off
client=off
EOL

# Systemd & SysV fallback
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable karos || true
    systemctl restart karos || true
else
    update-rc.d karos defaults
    service karos restart || true
fi

echo ">> Setup awal selesai"
echo ">> Akses WebUI: http://<LAN_IP>:8080"
EOF
chmod 755 $BUILD_DIR/DEBIAN/postinst

# --- Systemd service ---
cat > $BUILD_DIR/lib/systemd/system/karos.service <<EOF
[Unit]
Description=Karos RouterOS-like WebUI
After=network.target

[Service]
ExecStart=/usr/bin/karos-webui
Restart=always
User=karos

[Install]
WantedBy=multi-user.target
EOF

# --- SysV init fallback ---
cat > $BUILD_DIR/etc/init.d/karos <<'EOF'
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
chmod 755 $BUILD_DIR/etc/init.d/karos

# --- WebUI starter (full features interactive) ---
cat > $BUILD_DIR/usr/bin/karos-webui <<'EOF'
#!/usr/bin/env python3
from flask import Flask, render_template_string, request, redirect, url_for
import configparser, os

CONFIG_FILE = "/etc/karos/feature.conf"

app = Flask(__name__)
config = configparser.ConfigParser()
config.read(CONFIG_FILE)

HTML = """
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Karos RouterOS-like</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
<script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
</head>
<body class="bg-light">
<div class="container py-4">
<h1 class="mb-4">Karos WebUI</h1>

<form method="post" action="/update">
<h4>Network & VLAN</h4>
<div class="form-check">
<input class="form-check-input" type="checkbox" name="vlan" id="vlan" {% if config['vlan']['enabled']=='on' %}checked{% endif %}>
<label class="form-check-label" for="vlan">Enable VLAN</label>
</div>

<h4>DHCP / DNS</h4>
<div class="form-check">
<input class="form-check-input" type="checkbox" name="dhcp" id="dhcp" {% if config['dhcp']['enabled']=='on' %}checked{% endif %}>
<label class="form-check-label" for="dhcp">Enable DHCP</label>
</div>
<div class="form-check">
<input class="form-check-input" type="checkbox" name="dns" id="dns" {% if config['dns']['enabled']=='on' %}checked{% endif %}>
<label class="form-check-label" for="dns">Enable DNS</label>
</div>

<h4>Hotspot / Radius</h4>
<div class="form-check">
<input class="form-check-input" type="checkbox" name="hotspot" id="hotspot" {% if config['hotspot']['enabled']=='on' %}checked{% endif %}>
<label class="form-check-label" for="hotspot">Enable Hotspot</label>
</div>
<div class="form-check">
<input class="form-check-input" type="checkbox" name="radius" id="radius" {% if config['radius']['enabled']=='on' %}checked{% endif %}>
<label class="form-check-label" for="radius">Enable Radius</label>
</div>

<h4>Firewall</h4>
<div class="form-check">
<input class="form-check-input" type="checkbox" name="firewall" id="firewall" {% if config['firewall']['enabled']=='on' %}checked{% endif %}>
<label class="form-check-label" for="firewall">Enable Firewall</label>
</div>

<h4>PPP / PPTP</h4>
<div class="form-check">
<input class="form-check-input" type="checkbox" name="pppoe_server" id="pppoe_server" {% if config['pppoe']['server']=='on' %}checked{% endif %}>
<label class="form-check-label" for="pppoe_server">PPPoE Server</label>
</div>
<div class="form-check">
<input class="form-check-input" type="checkbox" name="pppoe_client" id="pppoe_client" {% if config['pppoe']['client']=='on' %}checked{% endif %}>
<label class="form-check-label" for="pppoe_client">PPPoE Client</label>
</div>
<div class="form-check">
<input class="form-check-input" type="checkbox" name="pptp_server" id="pptp_server" {% if config['pptp']['server']=='on' %}checked{% endif %}>
<label class="form-check-label" for="pptp_server">PPTP Server</label>
</div>
<div class="form-check">
<input class="form-check-input" type="checkbox" name="pptp_client" id="pptp_client" {% if config['pptp']['client']=='on' %}checked{% endif %}>
<label class="form-check-label" for="pptp_client">PPTP Client</label>
</div>

<br><button class="btn btn-primary" type="submit">Simpan & Restart Services</button>
</form>
</div>
</body>
</html>
"""

@app.route("/", methods=["GET"])
def index():
    config.read(CONFIG_FILE)
    return render_template_string(HTML, config=config)

@app.route("/update", methods=["POST"])
def update():
    config.read(CONFIG_FILE)
    config['vlan']['enabled'] = 'on' if request.form.get('vlan') else 'off'
    config['dhcp']['enabled'] = 'on' if request.form.get('dhcp') else 'off'
    config['dns']['enabled'] = 'on' if request.form.get('dns') else 'off'
    config['hotspot']['enabled'] = 'on' if request.form.get('hotspot') else 'off'
    config['radius']['enabled'] = 'on' if request.form.get('radius') else 'off'
    config['firewall']['enabled'] = 'on' if request.form.get('firewall') else 'off'
    config['pppoe']['server'] = 'on' if request.form.get('pppoe_server') else 'off'
    config['pppoe']['client'] = 'on' if request.form.get('pppoe_client') else 'off'
    config['pptp']['server'] = 'on' if request.form.get('pptp_server') else 'off'
    config['pptp']['client'] = 'on' if request.form.get('pptp_client') else 'off'
    with open(CONFIG_FILE, "w") as f:
        config.write(f)
    # Restart services (basic)
    os.system("systemctl restart dnsmasq hostapd pptpd || service dnsmasq restart || true")
    return redirect(url_for('index'))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
EOF
chmod 755 $BUILD_DIR/usr/bin/karos-webui

# --- Build .deb ---
DEB_FILE="/tmp/${PACKAGE_NAME}_full.deb"
echo ">> Membuat paket .deb full Karos..."
dpkg-deb --build "$BUILD_DIR" "$DEB_FILE"
echo ">> Selesai: $DEB_FILE"
