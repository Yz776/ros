#!/bin/bash
set -e

PKG="roslike"
VER="1.0-1"
WORKDIR="$(pwd)/${PKG}_${VER}"

echo ">> Membuat struktur paket $PKG"

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR/DEBIAN"
mkdir -p "$WORKDIR/usr/bin"
mkdir -p "$WORKDIR/lib/systemd/system"
mkdir -p "$WORKDIR/etc/init.d"
mkdir -p "$WORKDIR/etc/profile.d"

# --- control file ---
cat > "$WORKDIR/DEBIAN/control" <<EOF
Package: $PKG
Version: $VER
Section: net
Priority: optional
Architecture: all
Depends: python3-flask, iproute2, hostapd, dnsmasq, ppp, pptpd, mariadb-server
Maintainer: Admin <admin@example.com>
Description: RouterOS-like system (roslike)
 A Debian package that provides a RouterOS-like CLI and WebUI.
EOF

# --- postinst ---
cat > "$WORKDIR/DEBIAN/postinst" <<'EOF'
#!/bin/bash
set -e

echo ">> [roslike] Setup awal"

mkdir -p /etc/roslike/config
mkdir -p /var/log/roslike

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
    echo "root:$NEWPASS" | chpasswd

    cat > /etc/roslike/config/network.conf <<CFG
WAN=$WAN_IF
LAN=$LAN_IF
CFG

    touch /etc/roslike/config/.initialized
    echo ">> Setup awal selesai"
fi

# Buat user rosadmin kalau belum ada
if ! id "rosadmin" &>/dev/null; then
    useradd -m -s /usr/bin/roslike rosadmin || true
    echo "rosadmin:roslike" | chpasswd || true
    echo ">> User 'rosadmin' dibuat (password default: roslike)"
fi

# Aktifkan service
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
EOF
chmod 755 "$WORKDIR/DEBIAN/postinst"

# --- systemd service ---
cat > "$WORKDIR/lib/systemd/system/roslike.service" <<EOF
[Unit]
Description=RouterOS-like WebUI
After=network.target

[Service]
ExecStart=/usr/bin/roslike-webui
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# --- sysvinit fallback ---
cat > "$WORKDIR/etc/init.d/roslike" <<'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides: roslike
# Required-Start: $network
# Required-Stop: $network
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: RouterOS-like
### END INIT INFO

case "$1" in
  start) /usr/bin/roslike-webui & ;;
  stop) pkill -f roslike-webui ;;
  restart) pkill -f roslike-webui; /usr/bin/roslike-webui & ;;
  *) echo "Usage: /etc/init.d/roslike {start|stop|restart}"; exit 1 ;;
esac
exit 0
EOF
chmod 755 "$WORKDIR/etc/init.d/roslike"

# --- CLI utama ---
cat > "$WORKDIR/usr/bin/roslike" <<'EOF'
#!/bin/bash
# RouterOS-like CLI
while true; do
    echo -n "[roslike] > "
    read cmd args
    case "$cmd" in
        quit|exit) exit 0 ;;
        help) echo "Available commands: ip, user, system, quit" ;;
        ip) echo "IP configuration (stub)" ;;
        user) echo "User management (stub)" ;;
        system) echo "System settings (stub)" ;;
        *) echo "Unknown command: $cmd" ;;
    esac
done
EOF
chmod 755 "$WORKDIR/usr/bin/roslike"

# --- WebUI starter ---
cat > "$WORKDIR/usr/bin/roslike-webui" <<'EOF'
#!/usr/bin/env python3
from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    return "<h1>RouterOS-like WebUI</h1><p>Semua konfigurasi ada di sini.</p>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
EOF
chmod 755 "$WORKDIR/usr/bin/roslike-webui"

# --- Auto CLI untuk root & rosadmin ---
cat > "$WORKDIR/etc/profile.d/roslike.sh" <<'EOF'
#!/bin/bash
if [[ $EUID -eq 0 || $USER == "rosadmin" ]]; then
    if [[ -x /usr/bin/roslike ]]; then
        exec /usr/bin/roslike
    fi
fi
EOF
chmod 755 "$WORKDIR/etc/profile.d/roslike.sh"

# --- Build .deb ---
echo ">> Membuat paket .deb ..."
dpkg-deb --build "$WORKDIR"
echo ">> Selesai: $(pwd)/${PKG}_${VER}.deb"
