#!/bin/bash
set -e

BUILD_DIR=karos_build

echo ">> Membuat struktur paket Karos..."
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR/{DEBIAN,etc/karos,usr/bin,usr/lib/karos-webui/lib,usr/lib/karos-webui/static,usr/lib/karos-webui/templates}

# --- Control file ---
cat > $BUILD_DIR/DEBIAN/control <<EOF
Package: karos
Version: 1.0-1
Section: net
Priority: optional
Architecture: amd64
Depends: python3, python3-flask, python3-pip, iproute2, iptables, dnsmasq, hostapd, ppp, pptpd, mariadb-server, iputils-ping
Maintainer: Karos Dev <dev@karos.local>
Description: Karos - RouterOS-like advanced system
 WebUI with VLAN, PPPoE, PPTP, Hotspot, Firewall, Multi-WAN, Radius support
EOF

# --- Postinst script ---
cat > $BUILD_DIR/DEBIAN/postinst <<'EOF'
#!/bin/bash
set -e

# Create default config folders
mkdir -p /etc/karos
mkdir -p /var/lib/karos

# Create default shell
if ! id karos >/dev/null 2>&1; then
    useradd -r -s /usr/bin/karos-shell karos || true
fi

# Enable services
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable karos-webui
    systemctl restart karos-webui || true
else
    update-rc.d karos-webui defaults
    service karos-webui restart || true
fi

echo ">> Karos installed successfully."
echo ">> WebUI: http://<LAN_IP>:8080"
EOF
chmod 755 $BUILD_DIR/DEBIAN/postinst

# --- Systemd service ---
cat > $BUILD_DIR/lib/systemd/system/karos-webui.service <<'EOF'
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
cat > $BUILD_DIR/etc/init.d/karos-webui <<'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides: karos-webui
# Required-Start: $network
# Required-Stop: $network
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: Karos WebUI
### END INIT INFO

case "$1" in
  start) /usr/bin/karos-webui &
    ;;
  stop) pkill -f karos-webui
    ;;
  restart) pkill -f karos-webui && /usr/bin/karos-webui &
    ;;
  *) echo "Usage: $0 {start|stop|restart}"
    exit 1
    ;;
esac
exit 0
EOF
chmod 755 $BUILD_DIR/etc/init.d/karos-webui

# --- WebUI starter ---
cat > $BUILD_DIR/usr/bin/karos-webui <<'EOF'
#!/usr/bin/env python3
import os
from flask import Flask, render_template, request, redirect, url_for
app = Flask(__name__, template_folder="/usr/lib/karos-webui/templates", static_folder="/usr/lib/karos-webui/static")

@app.route("/")
def index():
    return render_template("index.html")

# Example VLAN page
@app.route("/vlan", methods=["GET", "POST"])
def vlan():
    if request.method == "POST":
        vlan_id = request.form.get("vlan_id")
        iface = request.form.get("iface")
        ip = request.form.get("ip")
        # Save to config
        with open("/etc/karos/vlan.conf", "a") as f:
            f.write(f"{vlan_id},{iface},{ip}\n")
        return redirect(url_for("vlan"))
    return render_template("vlan.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
EOF
chmod 755 $BUILD_DIR/usr/bin/karos-webui

# --- WebUI templates ---
cat > $BUILD_DIR/usr/lib/karos-webui/templates/index.html <<'EOF'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Karos WebUI</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container-fluid">
  <div class="row">
    <nav class="col-2 bg-light sidebar py-3">
      <ul class="nav flex-column">
        <li class="nav-item"><a class="nav-link" href="/">Dashboard</a></li>
        <li class="nav-item"><a class="nav-link" href="/vlan">VLAN</a></li>
      </ul>
    </nav>
    <main class="col-10 py-3">
      <h1>Karos WebUI</h1>
      <p>All features configurable here.</p>
    </main>
  </div>
</div>
</body>
</html>
EOF

cat > $BUILD_DIR/usr/lib/karos-webui/templates/vlan.html <<'EOF'
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Karos VLAN</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
<div class="container">
<h2>VLAN Configuration</h2>
<form method="POST">
  <div class="mb-3">
    <label class="form-label">VLAN ID</label>
    <input type="text" name="vlan_id" class="form-control" required>
  </div>
  <div class="mb-3">
    <label class="form-label">Interface</label>
    <input type="text" name="iface" class="form-control" required>
  </div>
  <div class="mb-3">
    <label class="form-label">IP Address</label>
    <input type="text" name="ip" class="form-control" required>
  </div>
  <button type="submit" class="btn btn-primary">Save VLAN</button>
</form>
</div>
</body>
</html>
EOF

# --- Build .deb ---
echo ">> Membuat paket .deb Karos..."
dpkg-deb --build $BUILD_DIR
echo ">> Selesai: $(pwd)/${BUILD_DIR}.deb"
