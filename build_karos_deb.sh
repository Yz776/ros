#!/bin/bash
set -e

VERSION="1.5"
PKG_NAME="karos"
BUILD_DIR="${PKG_NAME}_${VERSION}-1"
MODULE_DIR="$BUILD_DIR/usr/lib/$PKG_NAME/modules"
CONFIG_DIR="$BUILD_DIR/etc/$PKG_NAME"

echo ">> Membuat struktur paket..."
rm -rf $BUILD_DIR
mkdir -p $MODULE_DIR
mkdir -p $CONFIG_DIR
mkdir -p $BUILD_DIR/DEBIAN
mkdir -p $BUILD_DIR/usr/bin
mkdir -p $BUILD_DIR/lib/systemd/system
mkdir -p $BUILD_DIR/etc/init.d

# --- Control file ---
cat > $BUILD_DIR/DEBIAN/control <<EOF
Package: $PKG_NAME
Version: $VERSION-1
Section: base
Priority: optional
Architecture: all
Depends: python3, python3-flask, iproute2, hostapd, dnsmasq, ppp, pptpd, mariadb-server
Maintainer: KarOS Team
Description: KarOS Router OS like Mikrotik, multi-function, v1.5 final production
EOF

# --- Default config ---
cat > $CONFIG_DIR/config.json <<'EOF'
{
  "wan": "eth0",
  "lan": "eth1",
  "dhcp_enabled": false,
  "vlan_enabled": false,
  "wifi_enabled": false,
  "pppoe_server_enabled": false,
  "pptp_server_enabled": false,
  "firewall_enabled": false
}
EOF

# --- Example module: network ---
cat > $MODULE_DIR/network.py <<'EOF'
#!/usr/bin/env python3
import json, subprocess
CONFIG="/etc/karos/config.json"
cfg=json.load(open(CONFIG))
def set_ip(interface, ip, netmask):
    subprocess.run(f"ip addr add {ip}/{netmask} dev {interface}", shell=True)
    subprocess.run(f"ip link set dev {interface} up", shell=True)
if __name__=="__main__":
    set_ip(cfg["lan"], "192.168.88.1", "24")
EOF
chmod +x $MODULE_DIR/network.py

# --- WebUI Flask ---
cat > $BUILD_DIR/usr/bin/karos-webui <<'EOF'
#!/usr/bin/env python3
from flask import Flask, request, render_template_string
import subprocess
app = Flask(__name__)

WEBUI_TEMPLATE = """
<h1>KarOS v1.5 Final</h1>
<form method="post">
<input type="text" name="cli" placeholder="[karos]>">
<input type="submit" value="Execute">
</form>
<pre>{{output}}</pre>
"""

@app.route("/", methods=["GET","POST"])
def index():
    output=""
    if request.method=="POST":
        cmd=request.form.get("cli")
        try:
            output=subprocess.getoutput(cmd)
        except Exception as e:
            output=str(e)
    return render_template_string(WEBUI_TEMPLATE, output=output)

if __name__=="__main__":
    app.run(host="0.0.0.0", port=8080)
EOF
chmod +x $BUILD_DIR/usr/bin/karos-webui

# --- systemd service ---
cat > $BUILD_DIR/lib/systemd/system/karos.service <<EOF
[Unit]
Description=KarOS Router OS WebUI
After=network.target

[Service]
ExecStart=/usr/bin/karos-webui
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# --- SysVinit fallback ---
cat > $BUILD_DIR/etc/init.d/karos <<'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides: karos
# Required-Start: $network
# Required-Stop: $network
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: KarOS WebUI
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
chmod +x $BUILD_DIR/etc/init.d/karos

# --- Post install ---
cat > $BUILD_DIR/DEBIAN/postinst <<'EOF'
#!/bin/bash
echo ">> KarOS v1.5 Final Setup"

# Enable systemd or fallback to service
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable karos
    systemctl restart karos
else
    update-rc.d karos defaults
    service karos restart
fi

echo ">> Setup selesai. Akses WebUI: http://<LAN_IP>:8080"
EOF
chmod +x $BUILD_DIR/DEBIAN/postinst

# --- Build .deb ---
echo ">> Membuat paket .deb ..."
dpkg-deb --build $BUILD_DIR
echo ">> Selesai: $(pwd)/${BUILD_DIR}.deb"
