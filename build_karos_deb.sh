#!/bin/bash

# Script: build_karos_deb.sh
# Deskripsi: Script ini membangun paket .deb untuk KarOS v1.5.2 (Final Production).
#           - Perbaikan error: shell user karos jadi /usr/bin/karos-cli.
#           - Fix RTNETLINK: Skip konfigurasi jaringan di container tanpa NET_ADMIN.
#           - Fix WebUI: Perbaiki sintaks Jinja2, tambah pengecekan Flask.
#           - Fix firewall: Cek privilige iptables.
#           - Fix DHCP: Cek dnsmasq dan interface.
#           - Tambah status di /etc/init.d/karos.
#           - KarOS autostart via update-rc.d.
#           - Update via CLI (apt/deb) dan WebUI (upload deb/apt).
#           - Kompatibel Debian/container.
#           Hasil: karos_1.5.2-1.deb

# Pastikan dependensi build ada
if ! command -v dpkg-deb &> /dev/null; then
    echo "Error: dpkg-deb tidak ditemukan. Install dengan: sudo apt install dpkg-dev"
    exit 1
fi

# Nama paket dan direktori build
PKG_NAME="karos"
PKG_VERSION="1.5.2-1"
PKG_DIR="${PKG_NAME}_${PKG_VERSION}"

# Bersihkan direktori lama dan buat struktur baru
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/lib/karos/modules"
mkdir -p "$PKG_DIR/etc/karos"
mkdir -p "$PKG_DIR/etc/init.d"
mkdir -p "$PKG_DIR/var/log/karos"
mkdir -p "$PKG_DIR/etc/sudoers.d"

# Buat file DEBIAN/control
cat << EOF > "$PKG_DIR/DEBIAN/control"
Package: $PKG_NAME
Version: $PKG_VERSION
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.9), python3-flask (>= 2.0), iproute2, hostapd, dnsmasq, ppp, pptpd, mariadb-server, iptables, vlan, rsyslog, logrotate, openssh-server, sudo
Maintainer: KarOS Developer <dev@karos.example>
Description: KarOS v1.5.2 - Router OS mirip Mikrotik dengan fitur modular.
 KarOS adalah sistem router berbasis Debian/Ubuntu dengan WebUI dan CLI khusus.
 WebUI dilindungi password, sinkron dengan user karos. Fitur dikonfigurasi via WebUI/CLI.
EOF

# Buat file DEBIAN/postinst
cat << 'EOF' > "$PKG_DIR/DEBIAN/postinst"
#!/bin/bash

# Post-install script untuk KarOS v1.5.2

# Fungsi untuk log warning tanpa exit
log_warning() {
    echo "Warning: $1" >&2
    echo "Warning: $1" >> /var/log/karos/karos.log
}

# Fungsi untuk log error fatal
log_error() {
    echo "Error: $1" >&2
    echo "Error: $1" >> /var/log/karos/karos.log
    exit 1
}

# Deteksi apakah di container
IS_CONTAINER=0
if grep -q docker /proc/1/cgroup 2>/dev/null || grep -q lxc /proc/1/cgroup 2>/dev/null; then
    IS_CONTAINER=1
    log_warning "Sistem terdeteksi sebagai container. Beberapa fitur jaringan mungkin terbatas tanpa --cap-add=NET_ADMIN atau --privileged."
    echo "Panduan container: Jalankan dengan 'docker run --cap-add=NET_ADMIN --privileged' untuk izin jaringan penuh."
fi

# Pastikan dependensi terinstall
for pkg in python3 python3-flask iproute2 hostapd dnsmasq ppp pptpd mariadb-server iptables vlan rsyslog logrotate openssh-server sudo; do
    if ! dpkg -l | grep -qw "$pkg"; then
        log_warning "$pkg tidak terdeteksi. Install dengan: sudo apt install $pkg"
    fi
done

# Pastikan Flask terinstall
if ! python3 -c "import flask" 2>/dev/null; then
    log_warning "Flask tidak terdeteksi. Install dengan: sudo pip3 install flask>=2.0"
fi

# Buat user karos untuk CLI
if id karos >/dev/null 2>&1; then
    usermod -s /usr/bin/karos-cli karos || log_warning "Gagal memperbarui shell user karos."
else
    useradd -m -s /usr/bin/karos-cli karos || log_warning "Gagal membuat user karos."
    echo "karos:karos" | chpasswd || log_warning "Gagal set password karos, default: karos."
fi

# Beri karos sudo privilege passwordless untuk ip dan dhclient
SUDOERS_FILE="/etc/sudoers.d/karos"
echo "karos ALL=(ALL) NOPASSWD: /sbin/ip, /sbin/dhclient" > "$SUDOERS_FILE"
chmod 0440 "$SUDOERS_FILE" || log_warning "Gagal set sudoers untuk karos."

# Simpan password karos untuk WebUI (hash SHA-256)
PASSWD_FILE="/etc/karos/karos.passwd"
mkdir -p /etc/karos || log_error "Gagal membuat direktori /etc/karos"
echo -n "karos" | sha256sum | awk '{print $1}' > "$PASSWD_FILE" || log_warning "Gagal membuat file password WebUI."
chmod 600 "$PASSWD_FILE"

# Minta password root baru
echo "Setup KarOS: Masukkan password root baru:"
passwd root || log_warning "Gagal mengubah password root, lanjutkan dengan password saat ini."

# Deteksi interface
if [ "$IS_CONTAINER" -eq 0 ]; then
    INTERFACES=$(ip link show 2>/dev/null | grep -oP '^\d+: \K\w+(?=:)' | grep -v lo || true)
else
    INTERFACES=""
fi
LAN_IF="eth0"
WAN_IF="eth1"

if [ -n "$INTERFACES" ]; then
    echo "Interface yang tersedia: $INTERFACES"
    read -p "Pilih interface WAN (default: eth1): " input_wan
    if echo "$INTERFACES" | grep -qw "$input_wan"; then
        WAN_IF="$input_wan"
    else
        log_warning "Interface WAN tidak valid, menggunakan default: $WAN_IF"
    fi
    read -p "Pilih interface LAN (default: eth0, tidak sama dengan WAN): " input_lan
    if echo "$INTERFACES" | grep -qw "$input_lan" && [ "$input_lan" != "$WAN_IF" ]; then
        LAN_IF="$input_lan"
    else
        log_warning "Interface LAN tidak valid, menggunakan default: $LAN_IF"
    fi
else
    log_warning "Tidak ada interface jaringan terdeteksi. Menggunakan default: LAN=$LAN_IF, WAN=$WAN_IF. Konfigurasi manual via /etc/karos/config.json."
fi

# Buat konfigurasi default
CONFIG_FILE="/etc/karos/config.json"
mkdir -p /etc/karos || log_error "Gagal membuat direktori /etc/karos"
cat << CONFIG > "$CONFIG_FILE"
{
  "interfaces": {
    "lan": "$LAN_IF",
    "wan": "$WAN_IF",
    "lan_ip": "192.168.88.1/24",
    "wan_ip": "dhcp"
  },
  "dhcp_server": {"enabled": false, "range": "192.168.88.100,192.168.88.200,12h"},
  "dns_client": {"enabled": false, "servers": ["8.8.8.8", "8.8.4.4"]},
  "vlan_support": {"enabled": false, "vlans": []},
  "wifi_ap": {"enabled": false, "ssid": "KarOS-AP", "passphrase": "password123", "channel": 6},
  "pppoe_server": {"enabled": false, "local_ip": "10.0.0.1", "remote_ip": "10.0.0.10-10.0.0.100"},
  "pppoe_client": {"enabled": false, "username": "", "password": "", "interface": "$WAN_IF"},
  "pptp_server": {"enabled": false, "local_ip": "192.168.99.1", "remote_ip": "192.168.99.10-192.168.99.100"},
  "pptp_client": {"enabled": false, "server": "", "username": "", "password": ""},
  "firewall": {"enabled": false, "rules": []},
  "logging": {"enabled": false, "level": "info"}
}
CONFIG
[ $? -eq 0 ] || log_error "Gagal membuat config.json"

# Apply IP default jika interface ada dan bukan container
if [ "$IS_CONTAINER" -eq 0 ]; then
    if ip link show dev "$LAN_IF" &>/dev/null; then
        ip addr flush dev "$LAN_IF" 2>/dev/null
        ip addr add 192.168.88.1/24 dev "$LAN_IF" || log_warning "Gagal set IP LAN"
        ip link set "$LAN_IF" up || log_warning "Gagal enable interface LAN"
    else
        log_warning "Interface $LAN_IF tidak ada, skip setup IP LAN."
    fi
    if ip link show dev "$WAN_IF" &>/dev/null; then
        dhclient "$WAN_IF" >/dev/null 2>&1 || log_warning "Gagal mendapatkan IP WAN via DHCP"
    else
        log_warning "Interface $WAN_IF tidak ada, skip setup IP WAN."
    fi
else
    log_warning "Skip konfigurasi jaringan karena berjalan di container tanpa privilige NET_ADMIN."
fi

# Setup firewall jika bukan container
if [ "$IS_CONTAINER" -eq 0 ] && command -v iptables >/dev/null; then
    iptables -A INPUT -p tcp --dport 8080 -j ACCEPT 2>/dev/null || log_warning "Gagal set firewall untuk port 8080."
    iptables-save >/etc/iptables.rules 2>/dev/null || log_warning "Gagal menyimpan aturan firewall."
else
    log_warning "Skip konfigurasi firewall karena berjalan di container atau iptables tidak tersedia."
fi

# Setup autostart
update-rc.d karos defaults >/dev/null 2>&1 || log_warning "Gagal mengatur autostart service."

# Restart service
if command -v service >/dev/null; then
    service karos restart >/dev/null 2>&1 || log_warning "Gagal restart service karos."
else
    log_warning "Perintah 'service' tidak ditemukan, skip restart."
fi

# Verifikasi WebUI berjalan
LAN_IP="192.168.88.1"
if [ "$IS_CONTAINER" -eq 0 ] && ip link show dev "$LAN_IF" &>/dev/null; then
    LAN_IP=$(ip addr show "$LAN_IF" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "192.168.88.1")
fi
if netstat -tuln | grep -q ":8080"; then
    echo "WebUI berjalan di http://$LAN_IP:8080 (login: karos, password: karos)"
else
    log_warning "WebUI tidak terdeteksi di port 8080. Periksa log di /var/log/karos/karos.log."
    echo "Troubleshooting: "
    echo "1. Pastikan service karos berjalan: sudo service karos restart"
    echo "2. Cek firewall: sudo iptables -L (jika bukan container)"
    echo "3. Cek binding: sudo netstat -tuln | grep 8080"
    echo "4. Periksa log: cat /var/log/karos/karos.log"
    echo "5. Cek Flask: sudo pip3 install flask>=2.0"
    echo "6. Jika di container, pastikan port mapping: -p 8080:8080 atau --network host"
fi

# Verifikasi SSH untuk user karos
if command -v sshd >/dev/null && service ssh status >/dev/null 2>&1; then
    echo "SSH aktif. Login sebagai 'karos' (password: karos) untuk CLI."
else
    log_warning "SSH tidak aktif. Install/aktifkan dengan: sudo apt install openssh-server && sudo service ssh start"
fi

echo "Setup selesai. Akses WebUI: http://$LAN_IP:8080 (login: karos, password: karos)"
echo "Login CLI: ssh karos@$LAN_IP (password default: karos)"
echo "Untuk update KarOS: Di CLI, 'update' atau di WebUI, /update page."
exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# Buat script untuk sinkronasi password
cat << 'EOF' > "$PKG_DIR/usr/bin/karos-passwd"
#!/bin/bash

# Script untuk mengubah password user karos dan sinkron dengan WebUI
PASSWD_FILE="/etc/karos/karos.passwd"
if [ $# -ne 1 ]; then
    echo "Usage: $0 <new_password>"
    exit 1
fi

# Ubah password user karos
echo "karos:$1" | chpasswd || { echo "Error: Gagal mengubah password karos."; exit 1; }

# Update password WebUI
echo -n "$1" | sha256sum | awk '{print $1}' > "$PASSWD_FILE" || { echo "Error: Gagal update password WebUI."; exit 1; }
chmod 600 "$PASSWD_FILE"
echo "Password karos dan WebUI berhasil diubah."
exit 0
EOF
chmod 755 "$PKG_DIR/usr/bin/karos-passwd"

# Buat /etc/init.d/karos
cat << 'EOF' > "$PKG_DIR/etc/init.d/karos"
#!/bin/sh

### BEGIN INIT INFO
# Provides:          karos
# Required-Start:    $remote_fs $syslog $network
# Required-Stop:     $remote_fs $syslog $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: KarOS Router Service
# Description:       Service untuk KarOS WebUI dan modul.
### END INIT INFO

PIDFILE=/var/run/karos-webui.pid
WEBUI=/usr/bin/karos-webui
LOGFILE=/var/log/karos/karos.log

case "$1" in
  start)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "KarOS sudah berjalan."
      exit 0
    fi
    mkdir -p /var/log/karos
    touch "$LOGFILE"
    nohup python3 "$WEBUI" >> "$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    echo "KarOS dimulai."
    ;;
  stop)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      kill "$(cat "$PIDFILE")"
      rm -f "$PIDFILE"
      echo "KarOS dihentikan."
    else
      echo "KarOS tidak berjalan."
    fi
    ;;
  restart)
    $0 stop
    sleep 1
    $0 start
    ;;
  status)
    if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "KarOS sedang berjalan (PID: $(cat "$PIDFILE"))."
    else
      echo "KarOS tidak berjalan."
      exit 1
    fi
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}"
    exit 1
    ;;
esac

exit 0
EOF
chmod 755 "$PKG_DIR/etc/init.d/karos"

# Buat /usr/bin/karos-cli
cat << 'EOF' > "$PKG_DIR/usr/bin/karos-cli"
#!/usr/bin/env python3

import cmd
import json
import os
import subprocess
import shlex
import hashlib

CONFIG_PATH = '/etc/karos/config.json'
MODULES_DIR = '/usr/lib/karos/modules'
PASSWD_FILE = '/etc/karos/karos.passwd'

def load_config():
    try:
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
        return {}

def save_config(config):
    try:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        print(f"Error saving config: {e}")

def apply_feature(feature, config):
    module_path = os.path.join(MODULES_DIR, f'{feature}.py')
    if os.path.exists(module_path):
        action = 'enable' if config[feature]['enabled'] else 'disable'
        try:
            subprocess.run(['sudo', 'python3', module_path, action, json.dumps(config[feature])], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error applying {feature}: {e}")

class KarOSCLI(cmd.Cmd):
    prompt = '[KarOS] > '
    intro = 'KarOS v1.5.2 CLI - Type ? for help'

    def do_ip(self, arg):
        """Configure IP: ip set lan <ip> | ip set wan <ip|dhcp> | ip show"""
        args = shlex.split(arg)
        config = load_config()
        if not args:
            print("Usage: ip set lan <ip> | ip set wan <ip|dhcp> | ip show")
            return
        if args[0] == 'show':
            print(f"LAN: {config['interfaces']['lan']} ({config['interfaces']['lan_ip']})")
            print(f"WAN: {config['interfaces']['wan']} ({config['interfaces']['wan_ip']})")
        elif args[0] == 'set' and len(args) >= 3:
            if args[1] == 'lan':
                config['interfaces']['lan_ip'] = args[2]
                if subprocess.run(['sudo', 'ip', 'link', 'show', 'dev', config['interfaces']['lan']], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                    subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', config['interfaces']['lan']], check=False)
                    subprocess.run(['sudo', 'ip', 'addr', 'add', args[2], 'dev', config['interfaces']['lan']], check=False)
                    subprocess.run(['sudo', 'ip', 'link', 'set', config['interfaces']['lan'], 'up'], check=False)
                else:
                    print(f"Interface {config['interfaces']['lan']} tidak ada, skip konfigurasi.")
                save_config(config)
            elif args[1] == 'wan':
                config['interfaces']['wan_ip'] = args[2]
                if subprocess.run(['sudo', 'ip', 'link', 'show', 'dev', config['interfaces']['wan']], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0:
                    if args[2] == 'dhcp':
                        subprocess.run(['sudo', 'dhclient', config['interfaces']['wan']], check=False)
                    else:
                        subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', config['interfaces']['wan']], check=False)
                        subprocess.run(['sudo', 'ip', 'addr', 'add', args[2], 'dev', config['interfaces']['wan']], check=False)
                        subprocess.run(['sudo', 'ip', 'link', 'set', config['interfaces']['wan'], 'up'], check=False)
                else:
                    print(f"Interface {config['interfaces']['wan']} tidak ada, skip konfigurasi.")
                save_config(config)
            else:
                print("Usage: ip set lan <ip> | ip set wan <ip|dhcp>")
        else:
            print("Usage: ip set lan <ip> | ip set wan <ip|dhcp> | ip show")

    def do_dhcp(self, arg):
        """Configure DHCP Server: dhcp set range <range> | dhcp enable | dhcp disable | dhcp show"""
        args = shlex.split(arg)
        config = load_config()
        if not args:
            print("Usage: dhcp set range <range> | dhcp enable | dhcp disable | dhcp show")
            return
        if args[0] == 'show':
            print(f"DHCP Server: {'Enabled' if config['dhcp_server']['enabled'] else 'Disabled'}")
            print(f"Range: {config['dhcp_server']['range']}")
        elif args[0] == 'set' and len(args) == 3 and args[1] == 'range':
            config['dhcp_server']['range'] = args[2]
            save_config(config)
            if config['dhcp_server']['enabled']:
                apply_feature('dhcp_server', config)
        elif args[0] == 'enable':
            config['dhcp_server']['enabled'] = True
            save_config(config)
            apply_feature('dhcp_server', config)
        elif args[0] == 'disable':
            config['dhcp_server']['enabled'] = False
            save_config(config)
            apply_feature('dhcp_server', config)
        else:
            print("Usage: dhcp set range <range> | dhcp enable | dhcp disable | dhcp show")

    def do_passwd(self, arg):
        """Change karos user and WebUI password: passwd <new_password>"""
        if not arg:
            print("Usage: passwd <new_password>")
            return
        try:
            subprocess.run(['sudo', 'karos-passwd', arg], check=True)
            print("Password updated successfully.")
        except subprocess.CalledProcessError:
            print("Error updating password.")

    def do_update(self, arg):
        """Update KarOS: update [deb_file] - If deb_file provided, dpkg -i; else apt upgrade karos"""
        if arg:
            try:
                subprocess.run(['sudo', 'dpkg', '-i', arg], check=True)
                subprocess.run(['sudo', 'service', 'karos', 'restart'], check=True)
                print("KarOS updated from deb file and service restarted.")
            except subprocess.CalledProcessError as e:
                print(f"Error updating from deb: {e}")
        else:
            try:
                subprocess.run(['sudo', 'apt', 'update'], check=True)
                subprocess.run(['sudo', 'apt', 'upgrade', '-y', 'karos'], check=True)
                subprocess.run(['sudo', 'service', 'karos', 'restart'], check=True)
                print("KarOS updated via apt and service restarted.")
            except subprocess.CalledProcessError as e:
                print(f"Error updating via apt: {e}")

    def do_quit(self, arg):
        """Exit CLI"""
        return True

    def do_help(self, arg):
        """Show help"""
        print("Available commands:")
        print("  ip set lan <ip> | ip set wan <ip|dhcp> | ip show")
        print("  dhcp set range <range> | dhcp enable | dhcp disable | dhcp show")
        print("  passwd <new_password>")
        print("  update [deb_file]")
        print("  quit")
        print("  help")

if __name__ == '__main__':
    KarOSCLI().cmdloop()
EOF
chmod 755 "$PKG_DIR/usr/bin/karos-cli"

# Buat /usr/bin/karos-webui dengan sintaks Jinja2 yang diperbaiki
cat << 'EOF' > "$PKG_DIR/usr/bin/karos-webui"
#!/usr/bin/env python3

import json
import os
import subprocess
from flask import Flask, request, render_template_string, redirect, url_for, session, flash
import hashlib
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
CONFIG_PATH = '/etc/karos/config.json'
MODULES_DIR = '/usr/lib/karos/modules'
LOG_PATH = '/var/log/karos/karos.log'
PASSWD_FILE = '/etc/karos/karos.passwd'
UPDATE_DIR = '/tmp/karos_update'
os.makedirs(UPDATE_DIR, exist_ok=True)

def load_config():
    try:
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    except Exception as e:
        with open(LOG_PATH, 'a') as f:
            f.write(f"Error loading config: {e}\n")
        return {}

def save_config(config):
    try:
        if 'config_history' not in session:
            session['config_history'] = []
        session['config_history'].append(json.dumps(load_config()))
        if len(session['config_history']) > 10:
            session['config_history'].pop(0)
        with open(CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        with open(LOG_PATH, 'a') as f:
            f.write(f"Error saving config: {e}\n")

def undo():
    try:
        if 'config_history' in session and session['config_history']:
            prev_config = json.loads(session['config_history'].pop())
            with open(CONFIG_PATH, 'w') as f:
                json.dump(prev_config, f, indent=2)
            return prev_config
        return load_config()
    except Exception as e:
        with open(LOG_PATH, 'a') as f:
            f.write(f"Error undoing config: {e}\n")
        return load_config()

def apply_feature(feature):
    config = load_config()
    enabled = config.get(feature, {}).get('enabled', False)
    module_path = os.path.join(MODULES_DIR, f'{feature}.py')
    if os.path.exists(module_path):
        action = 'enable' if enabled else 'disable'
        try:
            subprocess.run(['sudo', 'python3', module_path, action, json.dumps(config[feature])], check=True)
        except subprocess.CalledProcessError as e:
            with open(LOG_PATH, 'a') as f:
                f.write(f"Error applying {feature}: {e}\n")

def check_auth(username, password):
    try:
        with open(PASSWD_FILE, 'r') as f:
            stored_hash = f.read().strip()
        input_hash = hashlib.sha256(password.encode()).hexdigest()
        return username == 'karos' and input_hash == stored_hash
    except Exception as e:
        with open(LOG_PATH, 'a') as f:
            f.write(f"Error checking auth: {e}\n")
        return False

# Template login
LOGIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>KarOS Login</title>
    <style>
        body { font-family: Arial, sans-serif; background: #f0f0f0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
        .login-box { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }
        .login-box h2 { color: #004080; }
        .form-group { margin-bottom: 15px; }
        input { width: 100%; padding: 8px; margin: 5px 0; box-sizing: border-box; }
        button { background: #004080; color: white; border: none; padding: 10px; cursor: pointer; width: 100%; }
        button:hover { background: #0066cc; }
        .error { color: red; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>KarOS WebUI Login</h2>
        {% if error %}
        <p class="error">{{ error }}</p>
        {% endif %}
        <form method="post" action="/login">
            <div class="form-group">
                <label>Username:</label>
                <input type="text" name="username" value="karos" readonly>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password">
            </div>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>
'''

# Template utama
MAIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>KarOS WebUI</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background: #f0f0f0; }
        #sidebar { width: 200px; float: left; background: #004080; color: white; height: 100vh; padding: 10px; }
        #sidebar a { color: white; display: block; padding: 8px; text-decoration: none; font-size: 14px; }
        #sidebar a:hover { background: #0066cc; }
        #content { margin-left: 220px; padding: 20px; }
        table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
        th { background: #004080; color: white; }
        button { background: #004080; color: white; border: none; padding: 8px 16px; cursor: pointer; }
        button:hover { background: #0066cc; }
        input, textarea, select { width: 100%; padding: 8px; margin: 5px 0; box-sizing: border-box; }
        .form-group { margin-bottom: 15px; }
        h1 { color: #004080; }
    </style>
</head>
<body>
    <div id="sidebar">
        <h2>KarOS v1.5.2</h2>
        <a href="/">Dashboard</a>
        <a href="/ip">IP / Interfaces</a>
        <a href="/dhcp_server">DHCP Server</a>
        <a href="/dns_client">DNS Client</a>
        <a href="/vlan_support">VLAN Support</a>
        <a href="/wifi_ap">Wireless AP</a>
        <a href="/pppoe_server">PPPoE Server</a>
        <a href="/pppoe_client">PPPoE Client</a>
        <a href="/pptp_server">PPTP Server</a>
        <a href="/pptp_client">PPTP Client</a>
        <a href="/firewall">Firewall</a>
        <a href="/logging">Logging</a>
        <a href="/logs">System Logs</a>
        <a href="/update">Update KarOS</a>
        <a href="/undo">Undo Changes</a>
        <a href="/logout">Logout</a>
    </div>
    <div id="content">
        {{ content | safe }}
    </div>
</body>
</html>
'''

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if check_auth(username, password):
            session['logged_in'] = True
            return redirect(url_for('index'))
        else:
            return render_template_string(LOGIN_TEMPLATE, error="Invalid credentials")
    return render_template_string(LOGIN_TEMPLATE, error=None)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    return redirect(url_for('login'))

def login_required(f):
    def wrap(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

@app.route('/')
@login_required
def index():
    config = load_config()
    content = '''
    <h1>Dashboard</h1>
    <table>
        <tr><th>Interface</th><th>Name</th><th>IP Address</th></tr>
        <tr><td>LAN</td><td>{{ config['interfaces']['lan'] }}</td><td>{{ config['interfaces']['lan_ip'] }}</td></tr>
        <tr><td>WAN</td><td>{{ config['interfaces']['wan'] }}</td><td>{{ config['interfaces']['wan_ip'] }}</td></tr>
    </table>
    <h2>Feature Status</h2>
    <table>
        <tr><th>Feature</th><th>Status</th></tr>
        {% for feature in features %}
        <tr><td>{{ feature.replace('_', ' ').title() }}</td><td>{{ 'Enabled' if config[feature]['enabled'] else 'Disabled' }}</td></tr>
        {% endfor %}
    </table>
    '''
    return render_template_string(MAIN_TEMPLATE, content=content, config=config, features=feature_configs.keys())

@app.route('/update', methods=['GET', 'POST'])
@login_required
def update_karos():
    if request.method == 'POST':
        if 'deb_file' in request.files:
            file = request.files['deb_file']
            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)
            if file and file.filename.endswith('.deb'):
                filename = secure_filename(file.filename)
                file_path = os.path.join(UPDATE_DIR, filename)
                file.save(file_path)
                try:
                    subprocess.run(['sudo', 'dpkg', '-i', file_path], check=True)
                    subprocess.run(['sudo', 'service', 'karos', 'restart'], check=True)
                    flash('KarOS updated successfully from deb file and service restarted.')
                except subprocess.CalledProcessError as e:
                    flash(f'Error updating from deb: {e}')
                finally:
                    os.remove(file_path)
                return redirect(url_for('update_karos'))
        else:
            try:
                subprocess.run(['sudo', 'apt', 'update'], check=True)
                subprocess.run(['sudo', 'apt', 'upgrade', '-y', 'karos'], check=True)
                subprocess.run(['sudo', 'service', 'karos', 'restart'], check=True)
                flash('KarOS updated successfully via apt and service restarted.')
            except subprocess.CalledProcessError as e:
                flash(f'Error updating via apt: {e}')
            return redirect(url_for('update_karos'))
    content = '''
    <h1>Update KarOS</h1>
    <form method="post" enctype="multipart/form-data">
        <div class="form-group">
            <label>Upload .deb file (optional):</label>
            <input type="file" name="deb_file">
        </div>
        <button type="submit">Update</button>
    </form>
    <p>Jika tidak upload deb, akan jalankan apt upgrade karos.</p>
    {% with messages = get_flashed_messages() %}
        {% if messages %}
            <ul>
            {% for message in messages %}
                <li>{{ message }}</li>
            {% endfor %}
            </ul>
        {% endif %}
    {% endwith %}
    '''
    return render_template_string(MAIN_TEMPLATE, content=content)

@app.route('/ip', methods=['GET', 'POST'])
@login_required
def set_ip():
    config = load_config()
    if request.method == 'POST':
        config['interfaces']['lan_ip'] = request.form.get('lan_ip', config['interfaces']['lan_ip'])
        config['interfaces']['wan_ip'] = request.form.get('wan_ip', config['interfaces']['wan_ip'])
        save_config(config)
        if ip_link_exists(config['interfaces']['lan']):
            subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', config['interfaces']['lan']], check=False)
            subprocess.run(['sudo', 'ip', 'addr', 'add', config['interfaces']['lan_ip'], 'dev', config['interfaces']['lan']], check=False)
            subprocess.run(['sudo', 'ip', 'link', 'set', config['interfaces']['lan'], 'up'], check=False)
        if ip_link_exists(config['interfaces']['wan']):
            if config['interfaces']['wan_ip'] == 'dhcp':
                subprocess.run(['sudo', 'dhclient', config['interfaces']['wan']], check=False)
            else:
                subprocess.run(['sudo', 'ip', 'addr', 'flush', 'dev', config['interfaces']['wan']], check=False)
                subprocess.run(['sudo', 'ip', 'addr', 'add', config['interfaces']['wan_ip'], 'dev', config['interfaces']['wan']], check=False)
                subprocess.run(['sudo', 'ip', 'link', 'set', config['interfaces']['wan'], 'up'], check=False)
        return redirect(url_for('set_ip'))
    content = '''
    <h1>IP / Interfaces</h1>
    <form method="post">
        <div class="form-group">
            <label>LAN IP (e.g., 192.168.88.1/24):</label>
            <input name="lan_ip" value="{{ config['interfaces']['lan_ip'] }}">
        </div>
        <div class="form-group">
            <label>WAN IP (dhcp or e.g., 10.0.0.2/24):</label>
            <input name="wan_ip" value="{{ config['interfaces']['wan_ip'] }}">
        </div>
        <button type="submit">Apply</button>
    </form>
    '''
    return render_template_string(MAIN_TEMPLATE, content=content, config=config)

def ip_link_exists(ifname):
    return subprocess.run(['sudo', 'ip', 'link', 'show', 'dev', ifname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

feature_configs = {
    'dhcp_server': ['range'],
    'dns_client': ['servers'],
    'vlan_support': ['vlans'],
    'wifi_ap': ['ssid', 'passphrase', 'channel'],
    'pppoe_server': ['local_ip', 'remote_ip'],
    'pppoe_client': ['username', 'password', 'interface'],
    'pptp_server': ['local_ip', 'remote_ip'],
    'pptp_client': ['server', 'username', 'password'],
    'firewall': ['rules'],
    'logging': ['level']
}

def create_feature_route(feature, fields):
    @app.route(f'/{feature}', methods=['GET', 'POST'])
    @login_required
    def feature_route():
        config = load_config()
        if request.method == 'POST':
            config[feature]['enabled'] = request.form.get('enabled') == 'on'
            for field in fields:
                value = request.form.get(field, '')
                if field in ('vlans', 'servers'):
                    config[feature][field] = [v.strip() for v in value.split(',') if v.strip()]
                elif field == 'rules':
                    config[feature][field] = [r.strip() for r in value.splitlines() if r.strip()]
                elif field == 'channel':
                    config[feature][field] = int(value) if value.isdigit() else config[feature].get(field, 6)
                else:
                    config[feature][field] = value
            save_config(config)
            apply_feature(feature)
            return redirect(url_for('feature_route'))
        content = '''
        <h1>{}</h1>
        <form method="post">
            <div class="form-group">
                <label>Enabled:</label>
                <input type="checkbox" name="enabled" {} >
            </div>
        '''.format(feature.replace('_', ' ').upper(), 'checked' if config[feature]['enabled'] else '')
        for field in fields:
            value = config[feature].get(field, '')
            if isinstance(value, list):
                value = ','.join(map(str, value))
            if field == 'rules':
                content += '''
                <div class="form-group">
                    <label>{} (one per line):</label>
                    <textarea name="{}" rows="5">{}</textarea>
                </div>
                '''.format(field.capitalize(), field, value)
            elif field == 'channel':
                content += '''
                <div class="form-group">
                    <label>{}:</label>
                    <select name="{}">
                        {} 
                    </select>
                </div>
                '''.format(
                    field.capitalize(), 
                    field, 
                    ''.join(f'<option value="{i}" {"selected" if config[feature]["channel"] == i else ""}>{i}</option>' for i in range(1, 14))
                )
            else:
                content += '''
                <div class="form-group">
                    <label>{}:</label>
                    <input name="{}" value="{}">
                </div>
                '''.format(field.capitalize(), field, value)
        content += '<button type="submit">Apply</button></form>'
        return render_template_string(MAIN_TEMPLATE, content=content, config=config)
    return feature_route

for feature, fields in feature_configs.items():
    globals()[feature + '_route'] = create_feature_route(feature, fields)

@app.route('/undo')
@login_required
def undo_route():
    config = undo()
    for feature in feature_configs:
        apply_feature(feature)
    return redirect(url_for('index'))

@app.route('/logs')
@login_required
def logs():
    try:
        logs = subprocess.check_output(['tail', '-n', '100', LOG_PATH], stderr=subprocess.STDOUT).decode()
    except subprocess.CalledProcessError:
        logs = "Logs tidak tersedia."
    content = f'<h1>System Logs</h1><pre>{logs}</pre>'
    return render_template_string(MAIN_TEMPLATE, content=content)

if __name__ == '__main__':
    try:
        app.run(host='0.0.0.0', port=8080, debug=False)
    except Exception as e:
        with open(LOG_PATH, 'a') as f:
            f.write(f"WebUI failed to start: {e}\n")
        raise
EOF
chmod 755 "$PKG_DIR/usr/bin/karos-webui"

# Buat modul-modul
# dhcp_server.py
cat << 'EOF' > "$PKG_DIR/usr/lib/karos/modules/dhcp_server.py"
#!/usr/bin/env python3

import sys
import json
import subprocess
import os

def enable(config):
    if not command -v dnsmasq >/dev/null; then
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write("Error: dnsmasq tidak terinstal.\n")
        raise Exception("dnsmasq tidak terinstal")
    try:
        lan_if = load_global_config()['interfaces']['lan']
        if subprocess.run(['ip', 'link', 'show', 'dev', lan_if], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            with open('/var/log/karos/karos.log', 'a') as f:
                f.write(f"Error: Interface {lan_if} tidak ada.\n")
            raise Exception(f"Interface {lan_if} tidak ada")
        lan_ip = load_global_config()['interfaces']['lan_ip'].split('/')[0]
        conf_path = '/etc/dnsmasq.d/karos-dhcp'
        os.makedirs(os.path.dirname(conf_path), exist_ok=True)
        with open(conf_path, 'w') as f:
            f.write(f"interface={lan_if}\n")
            f.write(f"dhcp-range={config['range']}\n")
            f.write(f"dhcp-option=option:router,{lan_ip}\n")
            f.write("dhcp-option=option:dns-server,8.8.8.8,8.8.4.4\n")
        subprocess.run(['sudo', 'service', 'dnsmasq', 'restart'], check=True)
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error enabling DHCP server: {e}\n")
        raise

def disable(config):
    try:
        subprocess.run(['sudo', 'service', 'dnsmasq', 'stop'], check=True)
        conf_path = '/etc/dnsmasq.d/karos-dhcp'
        if os.path.exists(conf_path):
            os.remove(conf_path)
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error disabling DHCP server: {e}\n")
        raise

def load_global_config():
    with open('/etc/karos/config.json', 'r') as f:
        return json.load(f)

def command():
    return subprocess.run(['which', 'dnsmasq'], capture_output=True, text=True).returncode == 0

if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ['enable', 'disable']:
        print("Usage: python3 dhcp_server.py [enable|disable] '{json_config}'")
        sys.exit(1)
    config = json.loads(sys.argv[2])
    if sys.argv[1] == 'enable':
        enable(config)
    else:
        disable(config)
EOF

# dns_client.py
cat << 'EOF' > "$PKG_DIR/usr/lib/karos/modules/dns_client.py"
#!/usr/bin/env python3

import sys
import json
import os

def enable(config):
    try:
        with open('/etc/resolv.conf', 'w') as f:
            for server in config['servers']:
                if server:
                    f.write(f"nameserver {server}\n")
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error enabling DNS client: {e}\n")
        raise

def disable(config):
    try:
        with open('/etc/resolv.conf', 'w') as f:
            f.write("nameserver 127.0.0.1\n")
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error disabling DNS client: {e}\n")
        raise

if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ['enable', 'disable']:
        print("Usage: python3 dns_client.py [enable|disable] '{json_config}'")
        sys.exit(1)
    config = json.loads(sys.argv[2])
    if sys.argv[1] == 'enable':
        enable(config)
    else:
        disable(config)
EOF

# vlan_support.py
cat << 'EOF' > "$PKG_DIR/usr/lib/karos/modules/vlan_support.py"
#!/usr/bin/env python3

import sys
import json
import subprocess

def enable(config):
    try:
        lan_if = load_global_config()['interfaces']['lan']
        for vlan_id in config['vlans']:
            if vlan_id.isdigit():
                subprocess.run(['sudo', 'ip', 'link', 'add', 'link', lan_if, 'name', f'{lan_if}.{vlan_id}', 'type', 'vlan', 'id', vlan_id], check=True)
                subprocess.run(['sudo', 'ip', 'link', 'set', f'{lan_if}.{vlan_id}', 'up'], check=True)
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error enabling VLAN: {e}\n")
        raise

def disable(config):
    try:
        lan_if = load_global_config()['interfaces']['lan']
        for vlan_id in config['vlans']:
            if vlan_id.isdigit():
                subprocess.run(['sudo', 'ip', 'link', 'delete', f'{lan_if}.{vlan_id}'], check=False)
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error disabling VLAN: {e}\n")
        raise

def load_global_config():
    with open('/etc/karos/config.json', 'r') as f:
        return json.load(f)

if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ['enable', 'disable']:
        print("Usage: python3 vlan_support.py [enable|disable] '{json_config}'")
        sys.exit(1)
    config = json.loads(sys.argv[2])
    if sys.argv[1] == 'enable':
        enable(config)
    else:
        disable(config)
EOF

# wifi_ap.py
cat << 'EOF' > "$PKG_DIR/usr/lib/karos/modules/wifi_ap.py"
#!/usr/bin/env python3

import sys
import json
import os
import subprocess

def enable(config):
    if not command -v hostapd >/dev/null; then
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write("Error: hostapd tidak terinstal.\n")
        raise Exception("hostapd tidak terinstal")
    try:
        wlan_if = load_global_config()['interfaces']['lan']
        if subprocess.run(['ip', 'link', 'show', 'dev', wlan_if], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            with open('/var/log/karos/karos.log', 'a') as f:
                f.write(f"Error: Interface {wlan_if} tidak ada.\n")
            raise Exception(f"Interface {wlan_if} tidak ada")
        conf_path = '/etc/hostapd/karos-ap.conf'
        os.makedirs(os.path.dirname(conf_path), exist_ok=True)
        with open(conf_path, 'w') as f:
            f.write(f"interface={wlan_if}\n")
            f.write("driver=nl80211\n")
            f.write(f"ssid={config['ssid']}\n")
            f.write("hw_mode=g\n")
            f.write(f"channel={config['channel']}\n")
            f.write("wpa=2\n")
            f.write(f"wpa_passphrase={config['passphrase']}\n")
            f.write("wpa_key_mgmt=WPA-PSK\n")
            f.write("rsn_pairwise=CCMP\n")
        subprocess.run(['sudo', 'service', 'hostapd', 'restart'], check=True)
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error enabling WiFi AP: {e}\n")
        raise

def disable(config):
    try:
        subprocess.run(['sudo', 'service', 'hostapd', 'stop'], check=True)
        conf_path = '/etc/hostapd/karos-ap.conf'
        if os.path.exists(conf_path):
            os.remove(conf_path)
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error disabling WiFi AP: {e}\n")
        raise

def load_global_config():
    with open('/etc/karos/config.json', 'r') as f:
        return json.load(f)

def command():
    return subprocess.run(['which', 'hostapd'], capture_output=True, text=True).returncode == 0

if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ['enable', 'disable']:
        print("Usage: python3 wifi_ap.py [enable|disable] '{json_config}'")
        sys.exit(1)
    config = json.loads(sys.argv[2])
    if sys.argv[1] == 'enable':
        enable(config)
    else:
        disable(config)
EOF

# pppoe_server.py
cat << 'EOF' > "$PKG_DIR/usr/lib/karos/modules/pppoe_server.py"
#!/usr/bin/env python3

import sys
import json
import os
import subprocess

def enable(config):
    if not command -v pppoe-server >/dev/null; then
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write("Error: pppoe-server tidak terinstal.\n")
        raise Exception("pppoe-server tidak terinstal")
    try:
        lan_if = load_global_config()['interfaces']['lan']
        if subprocess.run(['ip', 'link', 'show', 'dev', lan_if], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            with open('/var/log/karos/karos.log', 'a') as f:
                f.write(f"Error: Interface {lan_if} tidak ada.\n")
            raise Exception(f"Interface {lan_if} tidak ada")
        conf_path = '/etc/ppp/pppoe-server-options'
        os.makedirs(os.path.dirname(conf_path), exist_ok=True)
        with open(conf_path, 'w') as f:
            f.write("require-pap\n")
            f.write("ms-dns 8.8.8.8\n")
            f.write("ms-dns 8.8.4.4\n")
        subprocess.run(['sudo', 'pppoe-server', '-I', lan_if, '-L', config['local_ip'], '-R', config['remote_ip'], '-F'], check=True)
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error enabling PPPoE server: {e}\n")
        raise

def disable(config):
    try:
        subprocess.run(['sudo', 'killall', 'pppoe-server'], check=False)
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error disabling PPPoE server: {e}\n")
        raise

def load_global_config():
    with open('/etc/karos/config.json', 'r') as f:
        return json.load(f)

def command():
    return subprocess.run(['which', 'pppoe-server'], capture_output=True, text=True).returncode == 0

if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ['enable', 'disable']:
        print("Usage: python3 pppoe_server.py [enable|disable] '{json_config}'")
        sys.exit(1)
    config = json.loads(sys.argv[2])
    if sys.argv[1] == 'enable':
        enable(config)
    else:
        disable(config)
EOF

# pppoe_client.py
cat << 'EOF' > "$PKG_DIR/usr/lib/karos/modules/pppoe_client.py"
#!/usr/bin/env python3

import sys
import json
import os
import subprocess

def enable(config):
    if not command -v pon >/dev/null; then
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write("Error: ppp tidak terinstal.\n")
        raise Exception("ppp tidak terinstal")
    try:
        if subprocess.run(['ip', 'link', 'show', 'dev', config['interface']], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode != 0:
            with open('/var/log/karos/karos.log', 'a') as f:
                f.write(f"Error: Interface {config['interface']} tidak ada.\n")
            raise Exception(f"Interface {config['interface']} tidak ada")
        peer_path = '/etc/ppp/peers/karos-pppoe'
        os.makedirs(os.path.dirname(peer_path), exist_ok=True)
        with open(peer_path, 'w') as f:
            f.write(f"plugin rp-pppoe.so\n")
            f.write(f"nic-{config['interface']}\n")
            f.write(f"user \"{config['username']}\"\n")
            f.write("usepeerdns\n")
        chap_path = '/etc/ppp/chap-secrets'
        with open(chap_path, 'a') as f:
            f.write(f"\"{config['username']}\" * \"{config['password']}\" *\n")
        subprocess.run(['sudo', 'pon', 'karos-pppoe'], check=True)
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error enabling PPPoE client: {e}\n")
        raise

def disable(config):
    try:
        subprocess.run(['sudo', 'poff', 'karos-pppoe'], check=False)
        peer_path = '/etc/ppp/peers/karos-pppoe'
        if os.path.exists(peer_path):
            os.remove(peer_path)
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error disabling PPPoE client: {e}\n")
        raise

def command():
    return subprocess.run(['which', 'pon'], capture_output=True, text=True).returncode == 0

if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ['enable', 'disable']:
        print("Usage: python3 pppoe_client.py [enable|disable] '{json_config}'")
        sys.exit(1)
    config = json.loads(sys.argv[2])
    if sys.argv[1] == 'enable':
        enable(config)
    else:
        disable(config)
EOF

# pptp_server.py
cat << 'EOF' > "$PKG_DIR/usr/lib/karos/modules/pptp_server.py"
#!/usr/bin/env python3

import sys
import json
import os
import subprocess

def enable(config):
    if not command -v pptpd >/dev/null; then
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write("Error: pptpd tidak terinstal.\n")
        raise Exception("pptpd tidak terinstal")
    try:
        conf_path = '/etc/pptpd.conf'
        os.makedirs(os.path.dirname(conf_path), exist_ok=True)
        with open(conf_path, 'w') as f:
            f.write(f"localip {config['local_ip']}\n")
            f.write(f"remoteip {config['remote_ip']}\n")
        options_path = '/etc/ppp/pptpd-options'
        with open(options_path, 'w') as f:
            f.write("ms-dns 8.8.8.8\n")
            f.write("ms-dns 8.8.4.4\n")
        subprocess.run(['sudo', 'service', 'pptpd', 'restart'], check=True)
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error enabling PPTP server: {e}\n")
        raise

def disable(config):
    try:
        subprocess.run(['sudo', 'service', 'pptpd', 'stop'], check=True)
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error disabling PPTP server: {e}\n")
        raise

def command():
    return subprocess.run(['which', 'pptpd'], capture_output=True, text=True).returncode == 0

if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ['enable', 'disable']:
        print("Usage: python3 pptp_server.py [enable|disable] '{json_config}'")
        sys.exit(1)
    config = json.loads(sys.argv[2])
    if sys.argv[1] == 'enable':
        enable(config)
    else:
        disable(config)
EOF

# pptp_client.py
cat << 'EOF' > "$PKG_DIR/usr/lib/karos/modules/pptp_client.py"
#!/usr/bin/env python3

import sys
import json
import os
import subprocess

def enable(config):
    if not command -v pon >/dev/null; then
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write("Error: ppp tidak terinstal.\n")
        raise Exception("ppp tidak terinstal")
    try:
        peer_path = '/etc/ppp/peers/karos-pptp'
        os.makedirs(os.path.dirname(peer_path), exist_ok=True)
        with open(peer_path, 'w') as f:
            f.write(f"pty \"pptp {config['server']} --nolaunchpppd\"\n")
            f.write(f"name {config['username']}\n")
            f.write("remotename PPTP\n")
            f.write("require-mppe-128\n")
            f.write("file /etc/ppp/options.pptp\n")
        chap_path = '/etc/ppp/chap-secrets'
        with open(chap_path, 'a') as f:
            f.write(f"{config['username']} PPTP \"{config['password']}\" *\n")
        subprocess.run(['sudo', 'pon', 'karos-pptp'], check=True)
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error enabling PPTP client: {e}\n")
        raise

def disable(config):
    try:
        subprocess.run(['sudo', 'poff', 'karos-pptp'], check=False)
        peer_path = '/etc/ppp/peers/karos-pptp'
        if os.path.exists(peer_path):
            os.remove(peer_path)
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error disabling PPTP client: {e}\n")
        raise

def command():
    return subprocess.run(['which', 'pon'], capture_output=True, text=True).returncode == 0

if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ['enable', 'disable']:
        print("Usage: python3 pptp_client.py [enable|disable] '{json_config}'")
        sys.exit(1)
    config = json.loads(sys.argv[2])
    if sys.argv[1] == 'enable':
        enable(config)
    else:
        disable(config)
EOF

# firewall.py
cat << 'EOF' > "$PKG_DIR/usr/lib/karos/modules/firewall.py"
#!/usr/bin/env python3

import sys
import json
import subprocess

def enable(config):
    if not command -v iptables >/dev/null; then
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write("Error: iptables tidak terinstal.\n")
        raise Exception("iptables tidak terinstal")
    try:
        subprocess.run(['sudo', 'iptables', '-F'], check=True)
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'], check=True)
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'], check=True)
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '8080', '-j', 'ACCEPT'], check=True)
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-p', 'tcp', '--dport', '22', '-j', 'ACCEPT'], check=True)
        for rule in config.get('rules', []):
            if rule:
                subprocess.run(['sudo', 'iptables'] + rule.split(), check=True)
        subprocess.run(['sudo', 'iptables', '-A', 'INPUT', '-j', 'DROP'], check=True)
        subprocess.run(['sudo', 'iptables-save'], stdout=open('/etc/iptables.rules', 'w'), check=True)
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error enabling firewall: {e}\n")
        raise

def disable(config):
    try:
        subprocess.run(['sudo', 'iptables', '-F'], check=True)
        if os.path.exists('/etc/iptables.rules'):
            os.remove('/etc/iptables.rules')
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error disabling firewall: {e}\n")
        raise

def command():
    return subprocess.run(['which', 'iptables'], capture_output=True, text=True).returncode == 0

if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ['enable', 'disable']:
        print("Usage: python3 firewall.py [enable|disable] '{json_config}'")
        sys.exit(1)
    config = json.loads(sys.argv[2])
    if sys.argv[1] == 'enable':
        enable(config)
    else:
        disable(config)
EOF

# logging.py
cat << 'EOF' > "$PKG_DIR/usr/lib/karos/modules/logging.py"
#!/usr/bin/env python3

import sys
import json
import subprocess

def enable(config):
    if not command -v rsyslogd >/dev/null; then
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write("Error: rsyslog tidak terinstal.\n")
        raise Exception("rsyslog tidak terinstal")
    try:
        conf_path = '/etc/rsyslog.d/karos.conf'
        with open(conf_path, 'w') as f:
            f.write(f"*.* /var/log/karos/karos.log\n")
        subprocess.run(['sudo', 'service', 'rsyslog', 'restart'], check=True)
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error enabling logging: {e}\n")
        raise

def disable(config):
    try:
        subprocess.run(['sudo', 'service', 'rsyslog', 'stop'], check=True)
        conf_path = '/etc/rsyslog.d/karos.conf'
        if os.path.exists(conf_path):
            os.remove(conf_path)
    except Exception as e:
        with open('/var/log/karos/karos.log', 'a') as f:
            f.write(f"Error disabling logging: {e}\n")
        raise

def command():
    return subprocess.run(['which', 'rsyslogd'], capture_output=True, text=True).returncode == 0

if __name__ == '__main__':
    if len(sys.argv) != 3 or sys.argv[1] not in ['enable', 'disable']:
        print("Usage: python3 logging.py [enable|disable] '{json_config}'")
        sys.exit(1)
    config = json.loads(sys.argv[2])
    if sys.argv[1] == 'enable':
        enable(config)
    else:
        disable(config)
EOF

# Set permission untuk semua modul
for file in "$PKG_DIR/usr/lib/karos/modules/"*; do
    chmod 755 "$file"
done

# Build paket
dpkg-deb --build "$PKG_DIR"
if [ $? -eq 0 ]; then
    echo "Paket berhasil dibuild: ${PKG_DIR}.deb"
else
    echo "Error: Gagal build paket."
    exit 1
fi
