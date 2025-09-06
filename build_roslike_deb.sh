#!/bin/bash
set -e

PKG=roslike
VER=1.0
ARCH=all
DEBROOT=build/$PKG

# Bersihkan dulu
rm -rf build
mkdir -p $DEBROOT/DEBIAN
mkdir -p $DEBROOT/usr/local/bin
mkdir -p $DEBROOT/etc/systemd/system
mkdir -p $DEBROOT/etc/init.d
mkdir -p $DEBROOT/var/log/roslike
mkdir -p $DEBROOT/etc/roslike/config

### CONTROL FILE ###
cat > $DEBROOT/DEBIAN/control <<CTRL
Package: $PKG
Version: $VER
Section: net
Priority: optional
Architecture: $ARCH
Maintainer: Admin <admin@example.com>
Depends: python3, python3-flask, python3-requests, iproute2, dnsmasq, hostapd, ppp, pptpd
Description: RouterOS-like system for Debian/Ubuntu
CTRL

### POSTINST ###
cat > $DEBROOT/DEBIAN/postinst <<'POSTINST'
#!/bin/bash
set -e

echo ">> [roslike] Setup awal"

mkdir -p /etc/roslike/config
mkdir -p /var/log/roslike

# Setup wizard hanya sekali
if [ ! -f /etc/roslike/config/.initialized ]; then
    echo ""
    echo "=== RouterOS-like Initial Setup ==="

    echo "Daftar interface tersedia:"
    ip -o link show | awk -F': ' '{print NR ") " $2}'

    read -p "Pilih interface untuk WAN: " WAN_IF
    read -p "Pilih interface untuk LAN: " LAN_IF

    echo -n "Masukkan password baru untuk root: "
    read -s NEWPASS
    echo
    echo "root:$NEWPASS" | chpasswd || true

    cat > /etc/roslike/config/network.conf <<CFG
WAN=$WAN_IF
LAN=$LAN_IF
CFG

    touch /etc/roslike/config/.initialized
    echo ">> Setup awal selesai"
fi

# Aktifkan service (systemd atau sysvinit)
if [ "$(ps -p 1 -o comm=)" = "systemd" ]; then
    systemctl daemon-reload || true
    systemctl enable roslike || true
    systemctl restart roslike || true
else
    update-rc.d roslike defaults || true
    service roslike restart || true
fi

echo ">> RouterOS-like system terpasang."
echo "   Akses WebUI: http://<LAN_IP>:8080"
POSTINST
chmod 755 $DEBROOT/DEBIAN/postinst

### POSTRM ###
cat > $DEBROOT/DEBIAN/postrm <<'POSTRM'
#!/bin/bash
set -e
if [ "$(ps -p 1 -o comm=)" = "systemd" ]; then
    systemctl disable roslike || true
    systemctl stop roslike || true
else
    service roslike stop || true
fi
rm -rf /etc/roslike
POSTRM
chmod 755 $DEBROOT/DEBIAN/postrm

### SYSTEMD SERVICE ###
cat > $DEBROOT/etc/systemd/system/roslike.service <<'SERVICE'
[Unit]
Description=RouterOS-like WebUI
After=network.target

[Service]
ExecStart=/usr/bin/python3 /usr/local/bin/roslike_webui.py
Restart=always

[Install]
WantedBy=multi-user.target
SERVICE

### SYSVINIT SCRIPT ###
cat > $DEBROOT/etc/init.d/roslike <<'INIT'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          roslike
# Required-Start:    $network
# Required-Stop:     $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: RouterOS-like service
### END INIT INFO

case "$1" in
  start)
    /usr/bin/python3 /usr/local/bin/roslike_webui.py &
    ;;
  stop)
    pkill -f roslike_webui.py
    ;;
  restart)
    pkill -f roslike_webui.py
    /usr/bin/python3 /usr/local/bin/roslike_webui.py &
    ;;
  *)
    echo "Usage: $0 {start|stop|restart}"
    exit 1
esac
exit 0
INIT
chmod 755 $DEBROOT/etc/init.d/roslike

### FLASK WEBUI ###
cat > $DEBROOT/usr/local/bin/roslike_webui.py <<'WEBUI'
#!/usr/bin/python3
from flask import Flask, request, render_template_string
import os, subprocess

app = Flask(__name__)

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<title>RouterOS-like WebUI</title>
<style>
body { font-family: sans-serif; margin:20px; background:#f2f2f2; }
.card { background:#fff; padding:20px; margin-bottom:20px; border-radius:10px; box-shadow:0 2px 5px rgba(0,0,0,0.1); }
h2 { margin-top:0; }
button { padding:10px 15px; border:none; border-radius:5px; background:#007bff; color:#fff; }
input { padding:5px; }
</style>
</head>
<body>
<h1>RouterOS-like WebUI</h1>

<div class="card">
<h2>IP Settings</h2>
<form method="POST" action="/set_ip">
WAN: <input name="wan_ip" placeholder="192.168.1.2"><br>
LAN: <input name="lan_ip" placeholder="192.168.88.1"><br>
<button type="submit">Apply</button>
</form>
</div>

<div class="card">
<h2>DNS Settings</h2>
<form method="POST" action="/set_dns">
DNS1: <input name="dns1" placeholder="8.8.8.8"><br>
DNS2: <input name="dns2" placeholder="1.1.1.1"><br>
<button type="submit">Apply</button>
</form>
</div>

<div class="card">
<h2>DHCP Server</h2>
<form method="POST" action="/dhcp_toggle">
<button name="state" value="on">Enable</button>
<button name="state" value="off">Disable</button>
</form>
</div>

</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(TEMPLATE)

@app.route("/set_ip", methods=["POST"])
def set_ip():
    wan = request.form.get("wan_ip")
    lan = request.form.get("lan_ip")
    cfg = f"WAN_IP={wan}\nLAN_IP={lan}\n"
    with open("/etc/roslike/config/ip.conf", "w") as f:
        f.write(cfg)
    return "IP updated. <a href='/'>Back</a>"

@app.route("/set_dns", methods=["POST"])
def set_dns():
    dns1 = request.form.get("dns1")
    dns2 = request.form.get("dns2")
    resolv = f"nameserver {dns1}\n"
    if dns2: resolv += f"nameserver {dns2}\n"
    with open("/etc/resolv.conf", "w") as f:
        f.write(resolv)
    return "DNS updated. <a href='/'>Back</a>"

@app.route("/dhcp_toggle", methods=["POST"])
def dhcp_toggle():
    state = request.form.get("state")
    if state == "on":
        subprocess.call(["systemctl", "start", "dnsmasq"]) or subprocess.call(["service", "dnsmasq", "start"])
        return "DHCP enabled. <a href='/'>Back</a>"
    else:
        subprocess.call(["systemctl", "stop", "dnsmasq"]) or subprocess.call(["service", "dnsmasq", "stop"])
        return "DHCP disabled. <a href='/'>Back</a>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
WEBUI
chmod 755 $DEBROOT/usr/local/bin/roslike_webui.py

### BUILD .DEB ###
dpkg-deb --build --root-owner-group build/$PKG
mv build/$PKG.deb ${PKG}_${VER}_${ARCH}.deb

echo ">> Build selesai: ${PKG}_${VER}_${ARCH}.deb"
