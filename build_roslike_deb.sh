#!/bin/bash
set -e

PKGNAME="roslike"
VERSION="1.0"
ARCH="all"
WORKDIR="$(pwd)/${PKGNAME}_${VERSION}"

# Bersihkan build lama
rm -rf "$WORKDIR" "${PKGNAME}_${VERSION}-1.deb"
mkdir -p "$WORKDIR/DEBIAN"
mkdir -p "$WORKDIR/usr/bin"
mkdir -p "$WORKDIR/etc/systemd/system"
mkdir -p "$WORKDIR/etc/init.d"
mkdir -p "$WORKDIR/var/log/roslike"
mkdir -p "$WORKDIR/etc/roslike/config"

# =========================
# Control File
# =========================
cat > "$WORKDIR/DEBIAN/control" <<EOF
Package: $PKGNAME
Version: $VERSION-1
Section: net
Priority: optional
Architecture: $ARCH
Depends: bash, iproute2, iptables, dnsmasq, hostapd, ppp, pptpd, python3, python3-flask
Maintainer: Admin <admin@example.com>
Description: RouterOS-like system for Debian/Ubuntu
EOF

# =========================
# Postinst (setup awal)
# =========================
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

# Aktifkan WebUI
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable roslike-webui || true
    systemctl restart roslike-webui || true
else
    update-rc.d roslike-webui defaults || true
    service roslike-webui restart || true
fi

echo ">> RouterOS-like system terpasang."
echo "   Login SSH sebagai root untuk masuk ke CLI roslike."
echo "   Akses WebUI: http://<LAN_IP>:8080"
EOF
chmod 755 "$WORKDIR/DEBIAN/postinst"

# =========================
# CLI (roslike)
# =========================
cat > "$WORKDIR/usr/bin/roslike" <<'EOF'
#!/bin/bash
# CLI ala RouterOS
echo "RouterOS-like CLI (roslike)"
while true; do
    read -e -p "[roslike] > " CMD
    case "$CMD" in
        quit|exit) break ;;
        system\ reboot) echo "Rebooting..."; reboot ;;
        /interface\ print) ip -o link show ;;
        /ip\ address\ print) ip -o addr show ;;
        *) echo "Unknown command: $CMD" ;;
    esac
done
EOF
chmod 755 "$WORKDIR/usr/bin/roslike"

# =========================
# WebUI (roslike-webui)
# =========================
cat > "$WORKDIR/usr/bin/roslike-webui" <<'EOF'
#!/usr/bin/env python3
from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    return "<h1>RouterOS-like WebUI</h1><p>Konfigurasi di sini.</p>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
EOF
chmod 755 "$WORKDIR/usr/bin/roslike-webui"

# =========================
# systemd service
# =========================
cat > "$WORKDIR/etc/systemd/system/roslike-webui.service" <<EOF
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

# =========================
# Default shell ke roslike
# =========================
chsh -s /usr/bin/roslike root || true

# =========================
# Build .deb
# =========================
dpkg-deb --build "$WORKDIR"
mv "${PKGNAME}_${VERSION}.deb" "${PKGNAME}_${VERSION}-1.deb"

echo ">> Build selesai: ${PKGNAME}_${VERSION}-1.deb"
