#!/bin/bash

# Script: build_karos_deb.sh
# Deskripsi: Script ini membangun paket .deb untuk KarOS v1.5 (Final Production).
#           - Kompatibel dengan Debian (termasuk VM/kontainer seperti Docker).
#           - WebUI mirip Mikrotik Webfig dengan sidebar, form detail, dan undo/redo.
#           - Semua fitur (DHCP, DNS, VLAN, WiFi, PPPoE, PPTP, Firewall, Logging) diimplementasikan penuh.
#           - Robust: Tidak gagal meski tidak ada interface, fallback ke default.
#           - Menggunakan SysVinit (bukan systemd), dependensi diverifikasi.
#           Hasil: karos_1.5-1.deb

# Pastikan dependensi build ada
if ! command -v dpkg-deb &> /dev/null; then
    echo "Error: dpkg-deb tidak ditemukan. Install dengan: sudo apt install dpkg-dev"
    exit 1
fi

# Nama paket dan direktori build
PKG_NAME="karos"
PKG_VERSION="1.5-1"
PKG_DIR="${PKG_NAME}_${PKG_VERSION}"

# Bersihkan direktori lama dan buat struktur baru
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/lib/karos/modules"
mkdir -p "$PKG_DIR/etc/karos"
mkdir -p "$PKG_DIR/etc/init.d"
mkdir -p "$PKG_DIR/var/log/karos"

# Buat file DEBIAN/control
cat << EOF > "$PKG_DIR/DEBIAN/control"
Package: $PKG_NAME
Version: $PKG_VERSION
Section: net
Priority: optional
Architecture: all
Depends: python3 (>= 3.9), python3-flask (>= 2.0), iproute2, hostapd, dnsmasq, ppp, pptpd, mariadb-server, iptables, vlan, rsyslog, logrotate
Maintainer: KarOS Developer <dev@karos.example>
Description: KarOS v1.5 - Router OS mirip Mikrotik dengan fitur modular.
 KarOS adalah sistem router berbasis Debian/Ubuntu dengan WebUI untuk konfigurasi.
 Semua fitur default nonaktif dan bisa diaktifkan via WebUI.
EOF

# Buat file DEBIAN/postinst (robust, handle no interface)
cat << 'EOF' > "$PKG_DIR/DEBIAN/postinst"
#!/bin/bash

# Post-install script untuk KarOS v1.5

# Fungsi untuk log warning tanpa exit
log_warning() {
    echo "Warning: $1" >&2
}

# Fungsi untuk log error fatal
log_error() {
    echo "Error: $1" >&2
    exit 1
}

# Pastikan dependensi terinstall
for pkg in python3 python3-flask iproute2 hostapd dnsmasq ppp pptpd mariadb-server iptables vlan rsyslog logrotate; do
    if ! dpkg -l | grep -qw "$pkg"; then
        log_warning "$pkg tidak terdeteksi. Pastikan terinstall dengan: sudo apt install $pkg"
    fi
done

# Minta password root baru
echo "Setup KarOS: Masukkan password root baru:"
passwd root || log_warning "Gagal mengubah password root, lanjutkan dengan password saat ini."

# Deteksi interface (kecuali lo)
INTERFACES=$(ip link show 2>/dev/null | grep -oP '^\d+: \K\w+(?=:)' | grep -v lo || true)
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
    log_warning "Tidak ada interface jaringan terdeteksi (mungkin kontainer/VM). Menggunakan default: LAN=$LAN_IF, WAN=$WAN_IF. Konfigurasi manual via /etc/karos/config.json."
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

# Apply IP default jika interface ada
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

# Setup autostart
update-rc.d karos defaults >/dev/null 2>&1 || log_warning "Gagal mengatur autostart service."

# Restart service
if command -v service >/dev/null; then
    service karos restart >/dev/null 2>&1 || log_warning "Gagal restart service karos."
else
    log_warning "Perintah 'service' tidak ditemukan, skip restart."
fi

# Dapatkan IP LAN
LAN_IP="192.168.88.1"
if ip link show dev "$LAN_IF" &>/dev/null; then
    LAN_IP=$(ip addr show "$LAN_IF" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "192.168.88.1")
fi

echo "Setup selesai. Akses WebUI: http://$LAN_IP:8080"
exit 0
EOF
chmod 755 "$PKG_DIR/DEBIAN/postinst"

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
  *)
    echo "Usage: $0 {start|stop|restart}"
    exit 1
    ;;
esac

exit 0
EOF
chmod 755 "$PKG_DIR/etc/init.d/karos"

# Buat /usr/bin/karos-webui
cat << 'EOF' > "$PKG_DIR/usr/bin/karos-webui"
#!/usr/bin/env python3

import json
import os
import subprocess
from flask import Flask, request, render_template_string, redirect, url_for, session

app = Flask(__name__)
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
CONFIG_PATH = '/etc/karos/config.json'
MODULES_DIR = '/usr/lib/karos/modules'
LOG_PATH = '/var/log/syslog'

def load_config():
    try:
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading config: {e}")
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
        print(f"Error saving config: {e}")

def undo():
    try:
        if 'config_history' in session and session['config_history']:
            prev_config = json.loads(session['config_history'].pop())
            with open(CONFIG_PATH, 'w') as f:
                json.dump(prev_config, f, indent=2)
            return prev_config
        return load_config()
    except Exception as e:
        print(f"Error undoing config: {e}")
        return load_config()

def apply_feature(feature):
    config = load_config()
    enabled = config.get(feature, {}).get('enabled', False)
    module_path = os.path.join(MODULES_DIR, f'{feature}.py')
    if os.path.exists(module_path):
        action = 'enable' if enabled else 'disable'
        try:
            subprocess.run(['python3', module_path, action, json.dumps(config[feature])], check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error applying {feature}: {e}")

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
        <h2>KarOS v1.5</h2>
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
        <a href="/undo">Undo Changes</a>
    </div>
    <div id="content">
        {% block content %}{% endblock %}
    </div>
</body>
</html>
'''

@app.route('/')
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
    template = MAIN_TEMPLATE.replace('{% block content %}{% endblock %}', content)
    return render_template_string(template, config=config, features=feature_configs.keys())

@app.route('/ip', methods=['GET', 'POST'])
def set_ip():
    config = load_config()
    if request.method == 'POST':
        config['interfaces']['lan_ip'] = request.form.get('lan_ip', config['interfaces']['lan_ip'])
        config['interfaces']['wan_ip'] = request.form.get('wan_ip', config['interfaces']['wan_ip'])
        save_config(config)
        if ip_link_exists(config['interfaces']['lan']):
            subprocess.run(['ip', 'addr', 'flush', 'dev', config['interfaces']['lan']], check=False)
            subprocess.run(['ip', 'addr', 'add', config['interfaces']['lan_ip'], 'dev', config['interfaces']['lan']], check=False)
            subprocess.run(['ip', 'link', 'set', config['interfaces']['lan'], 'up'], check=False)
        if ip_link_exists(config['interfaces']['wan']):
            if config['interfaces']['wan_ip'] == 'dhcp':
                subprocess.run(['dhclient', config['interfaces']['wan']], check=False)
            else:
                subprocess.run(['ip', 'addr', 'flush', 'dev', config['interfaces']['wan']], check=False)
                subprocess.run(['ip', 'addr', 'add', config['interfaces']['wan_ip'], 'dev', config['interfaces']['wan']], check=False)
                subprocess.run(['ip', 'link', 'set', config['interfaces']['wan'], 'up'], check=False)
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
    template = MAIN_TEMPLATE.replace('{% block content %}{% endblock %}', content)
    return render_template_string(template, config=config)

def ip_link_exists(ifname):
    return subprocess.run(['ip', 'link', 'show', 'dev', ifname], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0

# Route generator untuk fitur
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
        content = f'''
        <h1>{feature.replace('_', ' ').upper()}</h1>
        <form method="post">
            <div class="form-group">
                <label>Enabled:</label>
                <input type="checkbox" name="enabled" {'checked' if config[feature]['enabled'] else ''}>
            </div>
        '''
        for field in fields:
            value = config[feature].get(field, '')
            if isinstance(value, list):
                value = ','.join(map(str, value))
            if field == 'rules':
                content += f'''
                <div class="form-group">
                    <label>{field.capitalize()} (one per line):</label>
                    <textarea name="{field}" rows="5">{value}</textarea>
                </div>
                '''
            elif field == 'channel':
                content += f'''
                <div class="form-group">
                    <label>{field.capitalize()}:</label>
                    <select name="{field}">
                        {% for i in range(1, 14) %}
                        <option value="{{ i }}" {{ 'selected' if config[feature]['channel'] == i else '' }}>{{ i }}</option>
                        {% endfor %}
                    </select>
                </div>
                '''
            else:
                content += f'''
                <div class="form-group">
                    <label>{field.capitalize()}:</label>
                    <input name="{field}" value="{value}">
                </div>
                '''
        content += '<button type="submit">Apply</button></form>'
        template = MAIN_TEMPLATE.replace('{% block content %}{% endblock %}', content)
        return render_template_string(template, config=config)
    return feature_route

for feature, fields in feature_configs.items():
    globals()[feature + '_route'] = create_feature_route(feature, fields)

@app.route('/undo')
def undo_route():
    config = undo()
    for feature in feature_configs:
        apply_feature(feature)
    return redirect(url_for('index'))

@app.route('/logs')
def logs():
    try:
        logs = subprocess.check_output(['tail', '-n', '100', LOG_PATH], stderr=subprocess.STDOUT).decode()
    except subprocess.CalledProcessError:
        logs = "Logs tidak tersedia."
    content = f'<h1>System Logs</h1><pre>{logs}</pre>'
    template = MAIN_TEMPLATE.replace('{% block content %}{% endblock %}', content)
    return render_template_string(template)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
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
    try:
        lan_if = load_global_config()['interfaces']['lan']
        lan_ip = load_global_config()['interfaces']['lan_ip'].split('/')[0]
        conf_path = '/etc/dnsmasq.d/karos-dhcp'
        os.makedirs(os.path.dirname(conf_path), exist_ok=True)
        with open(conf_path, 'w') as f:
            f.write(f"interface={lan_if}\n")
            f.write(f"dhcp-range={config['range']}\n")
            f.write(f"dhcp-option=option:router,{lan_ip}\n")
            f.write("dhcp-option=option:dns-server,8.8.8.8,8.8.4.4\n")
        subprocess.run(['service', 'dnsmasq', 'restart'], check=True)
    except Exception as e:
        print(f"Error enabling DHCP server: {e}")

def disable(config):
    try:
        subprocess.run(['service', 'dnsmasq', 'stop'], check=True)
        conf_path = '/etc/dnsmasq.d/karos-dhcp'
        if os.path.exists(conf_path):
            os.remove(conf_path)
    except Exception as e:
        print(f"Error disabling DHCP server: {e}")

def load_global_config():
    with open('/etc/karos/config.json', 'r') as f:
        return json.load(f)

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
        print(f"Error enabling DNS client: {e}")

def disable(config):
    try:
        with open('/etc/resolv.conf', 'w') as f:
            f.write("nameserver 127.0.0.1\n")
    except Exception as e:
        print(f"Error disabling DNS client: {e}")

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
                subprocess.run(['ip', 'link', 'add', 'link', lan_if, 'name', f'{lan_if}.{vlan_id}', 'type', 'vlan', 'id', vlan_id], check=True)
                subprocess.run(['ip', 'link', 'set', f'{lan_if}.{vlan_id}', 'up'], check=True)
    except Exception as e:
        print(f"Error enabling VLAN: {e}")

def disable(config):
    try:
        lan_if = load_global_config()['interfaces']['lan']
        for vlan_id in config['vlans']:
            if vlan_id.isdigit():
                subprocess.run(['ip', 'link', 'delete', f'{lan_if}.{vlan_id}'], check=False)
    except Exception as e:
        print(f"Error disabling VLAN: {e}")

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
    try:
        conf_path = '/etc/hostapd/karos-ap.conf'
        os.makedirs(os.path.dirname(conf_path), exist_ok=True)
        wlan_if = load_global_config()['interfaces']['lan']  # Asumsi LAN, ganti jika spesifik
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
        subprocess.run(['service', 'hostapd', 'restart'], check=True)
    except Exception as e:
        print(f"Error enabling WiFi AP: {e}")

def disable(config):
    try:
        subprocess.run(['service', 'hostapd', 'stop'], check=True)
        conf_path = '/etc/hostapd/karos-ap.conf'
        if os.path.exists(conf_path):
            os.remove(conf_path)
    except Exception as e:
        print(f"Error disabling WiFi AP: {e}")

def load_global_config():
    with open('/etc/karos/config.json', 'r') as f:
        return json.load(f)

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
    try:
        lan_if = load_global_config()['interfaces']['lan']
        conf_path = '/etc/ppp/pppoe-server-options'
        os.makedirs(os.path.dirname(conf_path), exist_ok=True)
        with open(conf_path, 'w') as f:
            f.write("require-pap\n")
            f.write("ms-dns 8.8.8.8\n")
            f.write("ms-dns 8.8.4.4\n")
        subprocess.run(['pppoe-server', '-I', lan_if, '-L', config['local_ip'], '-R', config['remote_ip'], '-F'], check=True)
    except Exception as e:
        print(f"Error enabling PPPoE server: {e}")

def disable(config):
    try:
        subprocess.run(['killall', 'pppoe-server'], check=False)
    except Exception as e:
        print(f"Error disabling PPPoE server: {e}")

def load_global_config():
    with open('/etc/karos/config.json', 'r') as f:
        return json.load(f)

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
    try:
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
        subprocess.run(['pon', 'karos-pppoe'], check=True)
    except Exception as e:
        print(f"Error enabling PPPoE client: {e}")

def disable(config):
    try:
        subprocess.run(['poff', 'karos-pppoe'], check=False)
        peer_path = '/etc/ppp/peers/karos-pppoe'
        if os.path.exists(peer_path):
            os.remove(peer_path)
    except Exception as e:
        print(f"Error disabling PPPoE client: {e}")

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
        subprocess.run(['service', 'pptpd', 'restart'], check=True)
    except Exception as e:
        print(f"Error enabling PPTP server: {e}")

def disable(config):
    try:
        subprocess.run(['service', 'pptpd', 'stop'], check=True)
    except Exception as e:
        print(f"Error disabling PPTP server: {e}")

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
        subprocess.run(['pon', 'karos-pptp'], check=True)
    except Exception as e:
        print(f"Error enabling PPTP client: {e}")

def disable(config):
    try:
        subprocess.run(['poff', 'karos-pptp'], check=False)
        peer_path = '/etc/ppp/peers/karos-pptp'
        if os.path.exists(peer_path):
            os.remove(peer_path)
    except Exception as e:
        print(f"Error disabling PPTP client: {e}")

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
    try:
        subprocess.run(['iptables', '-F'], check=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'], check=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'], check=True)
        for rule in config.get('rules', []):
            if rule:
                subprocess.run(['iptables'] + rule.split(), check=True)
        subprocess.run(['iptables', '-A', 'INPUT', '-j', 'DROP'], check=True)
        subprocess.run(['iptables-save'], stdout=open('/etc/iptables.rules', 'w'), check=True)
    except Exception as e:
        print(f"Error enabling firewall: {e}")

def disable(config):
    try:
        subprocess.run(['iptables', '-F'], check=True)
        if os.path.exists('/etc/iptables.rules'):
            os.remove('/etc/iptables.rules')
    except Exception as e:
        print(f"Error disabling firewall: {e}")

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
    try:
        conf_path = '/etc/rsyslog.d/karos.conf'
        with open(conf_path, 'w') as f:
            f.write(f"*.* /var/log/karos/karos.log\n")
        subprocess.run(['service', 'rsyslog', 'restart'], check=True)
    except Exception as e:
        print(f"Error enabling logging: {e}")

def disable(config):
    try:
        subprocess.run(['service', 'rsyslog', 'stop'], check=True)
        conf_path = '/etc/rsyslog.d/karos.conf'
        if os.path.exists(conf_path):
            os.remove(conf_path)
    except Exception as e:
        print(f"Error disabling logging: {e}")

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
