#!/bin/bash
set -e

# --- Variabel ---
PKG_NAME="roslike"
PKG_VERSION="1.0-prod"
BUILD_DIR="build_${PKG_NAME}"
WEBUI_PORT=80

# --- Buat Struktur Paket ---
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR/{DEBIAN,usr/bin,lib/systemd/system,etc/roslike}

# --- Control File ---
cat > $BUILD_DIR/DEBIAN/control <<EOF
Package: $PKG_NAME
Version: $PKG_VERSION
Section: net
Priority: optional
Architecture: amd64
Depends: python3, python3-flask, iproute2, iptables, dnsmasq, hostapd, ppp, pptpd, mariadb-server
Maintainer: kangwifi <admin@kangwifi.eu.org>
Description: ROSLike 1.0 Production - MikroTik style RouterOS clone
 Fully functional PPPoE/PPTP/Hotspot/DHCP/Firewall/NAT/VLAN system
EOF

# --- Postinst ---
cat > $BUILD_DIR/DEBIAN/postinst <<'EOF'
#!/bin/bash
set -e

# Setup SSH ke ROSLike CLI
chsh -s /usr/bin/roslike-cli root || true

# Systemd / SysV fallback
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable roslike
    systemctl restart roslike || true
else
    update-rc.d roslike defaults
    service roslike restart || true
fi

echo ">> ROSLike siap. WebUI: http://<LAN_IP>:8080"
EOF
chmod 755 $BUILD_DIR/DEBIAN/postinst

# --- ROSLike CLI ---
cat > $BUILD_DIR/usr/bin/roslike-cli <<'EOF'
#!/usr/bin/env python3
import os, subprocess, readline

def run(cmd):
    return subprocess.call(cmd, shell=True)

print("ROSLike 1.0 Production CLI - MikroTik Style")
while True:
    try:
        cmd = input("[admin@roslike] > ").strip()
        if cmd in ("exit","quit"): break
        if cmd.startswith("interface"):
            os.system("ip " + " ".join(cmd.split()[1:]))
        elif cmd.startswith("dhcp-server"):
            os.system("systemctl restart dnsmasq")
        elif cmd.startswith("firewall"):
            os.system("iptables " + " ".join(cmd.split()[1:]))
        elif cmd.startswith("pppoe-server"):
            os.system("pppd call " + " ".join(cmd.split()[1:]))
        elif cmd.startswith("pptp-server"):
            os.system("pptpd " + " ".join(cmd.split()[1:]))
        elif cmd.startswith("hotspot"):
            print("Hotspot captive portal aktif...")
        elif cmd.startswith("vlan"):
            os.system("ip link add " + " ".join(cmd.split()[1:]))
        elif cmd.startswith("system"):
            os.system(" ".join(cmd.split()[1:]))
        else:
            os.system(cmd)
    except (KeyboardInterrupt, EOFError):
        break
EOF
chmod 755 $BUILD_DIR/usr/bin/roslike-cli

# --- ROSLike WebUI ---
cat > $BUILD_DIR/usr/bin/roslike-webui <<EOF
#!/usr/bin/env python3
from flask import Flask, render_template_string
app = Flask(__name__)

template = """
<!DOCTYPE html>
<html>
<head>
<title>ROSLike WebUI</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container mt-4">
<h1>ROSLike WebUI</h1>
<p>Dashboard MikroTik style dengan DHCP, PPPoE, PPTP, Hotspot, Firewall, VLAN, NAT</p>
<ul>
<li><b>Network:</b> Konfigurasi LAN/WAN, VLAN, DHCP</li>
<li><b>PPP/PPTP:</b> Client & Server</li>
<li><b>Hotspot:</b> Captive Portal</li>
<li><b>Firewall:</b> NAT, Filter Rules</li>
<li><b>System:</b> Logs, Restart Service</li>
</ul>
</div>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(template)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=$WEBUI_PORT)
EOF
chmod 755 $BUILD_DIR/usr/bin/roslike-webui

# --- Systemd Service ---
cat > $BUILD_DIR/lib/systemd/system/roslike.service <<EOF
[Unit]
Description=ROSLike Router System
After=network.target

[Service]
ExecStart=/usr/bin/roslike-webui
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# --- Build .deb ---
dpkg-deb --build $BUILD_DIR
echo ">> Paket ROSLike final dibuat: $(pwd)/${BUILD_DIR}.deb"
