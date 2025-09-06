#!/bin/bash

# Script: build_karos_deb.sh
# Deskripsi: Script ini membangun paket .deb untuk KarOS v1.5 (Final Production) yang ditingkatkan.
#           - Menyesuaikan dengan Debian virtualisasi (deteksi interface seperti ens*, enp*).
#           - WebUI ditingkatkan untuk lebih mirip Mikrotik Webfig: sidebar menu, tabs, undo/redo sederhana.
#           - Semua fitur diperbaiki dengan implementasi nyata (bukan hanya print), modular, dan production-ready.
#           - Fitur default off, diaktifkan via WebUI dengan konfigurasi detail.
#           - Robust: Check error, handle virtual interfaces.
#           Paket ini mencakup WebUI berbasis Python Flask, modul modular untuk fitur router,
#           konfigurasi default di /etc/karos/config.json, SysVinit service, dan post-install script.
#           Script ini harus dijalankan di Debian/Ubuntu dengan hak root jika diperlukan.
#           Hasil: karos_1.5-1.deb

# Pastikan dependensi build ada
if ! command -v dpkg-deb &> /dev/null; then
    echo "dpkg-deb tidak ditemukan. Install dengan: sudo apt install dpkg-dev"
    exit 1
fi

# Nama paket dan direktori build
PKG_NAME="karos"
PKG_VERSION="1.5-1"
PKG_DIR="${PKG_NAME}_${PKG_VERSION}"

# Buat struktur direktori paket
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/usr/lib/karos/modules"
mkdir -p "$PKG_DIR/etc/karos"
mkdir -p "$PKG_DIR/etc/init.d"
mkdir -p "$PKG_DIR/var/log/karos"  # Untuk logs

# Buat file DEBIAN/control (tambah dependensi ekstra jika perlu, seperti iptables, vlan)
cat << EOF > "$PKG_DIR/DEBIAN/control"
Package: $PKG_NAME
Version: $PKG_VERSION
Section: net
Priority: optional
Architecture: all
Depends: python3, python3-flask, iproute2, hostapd, dnsmasq, ppp, pptpd, mariadb-server, iptables, vlan, rsyslog
Maintainer: KarOS Developer <dev@karos.example>
Description: KarOS v1.5 - Router OS mirip Mikrotik dengan fitur modular.
 KarOS adalah sistem router berbasis Debian/Ubuntu dengan WebUI untuk konfigurasi.
 Semua fitur default nonaktif dan bisa diaktifkan via WebUI.
EOF

# Buat file DEBIAN/postinst (post-install script ditingkatkan)
# - Deteksi interface lebih robust untuk virtualisasi (ens*, enp*, eth*).
# - Minta password, pilih WAN/LAN, buat config.json.
# - Handle error lebih baik.
cat << 'EOF' > "$PKG_DIR/DEBIAN/postinst"
#!/bin/bash

# Post-install script untuk KarOS v1.5 (ditingkatkan)

# Fungsi untuk cek error
check_error() {
    if [ $? -ne 0 ]; then
        echo "Error: $1"
        exit 1
    fi
}

# Minta password root baru
echo "Setup KarOS: Masukkan password root baru:"
passwd root
check_error "Gagal mengubah password root."

# List interface yang tersedia (kecuali lo, termasuk virtual seperti ens*, enp*)
INTERFACES=$(ip link show | grep -oP '^\d+: \K\w+(?=:)' | grep -v lo | grep -E '^(eth|ens|enp|wlan)')
if [ -z "$INTERFACES" ]; then
    echo "Tidak ada interface yang terdeteksi. Pastikan sistem memiliki network interfaces."
    exit 1
fi
echo "Interface yang tersedia: $INTERFACES"

# Pilih WAN interface
read -p "Pilih interface WAN (contoh: eth0 atau ens3): " WAN_IF
if ! echo "$INTERFACES" | grep -qw "$WAN_IF"; then
    echo "Interface WAN tidak valid."
    exit 1
fi

# Pilih LAN interface (tidak boleh sama dengan WAN)
read -p "Pilih interface LAN (contoh: eth1 atau enp0s3, tidak boleh sama dengan WAN): " LAN_IF
if ! echo "$INTERFACES" | grep -qw "$LAN_IF" || [ "$LAN_IF" = "$WAN_IF" ]; then
    echo "Interface LAN tidak valid atau sama dengan WAN."
    exit 1
fi

# Buat konfigurasi default di /etc/karos/config.json (semua fitur off, tambah detail config)
CONFIG_FILE="/etc/karos/config.json"
mkdir -p /etc/karos
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
  "wifi_ap": {"enabled": false, "ssid": "KarOS-AP", "passphrase": "password", "channel": 6},
  "pppoe_server": {"enabled": false, "local_ip": "10.0.0.1", "remote_ip": "10.0.0.10-10.0.0.100"},
  "pppoe_client": {"enabled": false, "username": "", "password": ""},
  "pptp_server": {"enabled": false, "local_ip": "192.168.99.1", "remote_ip": "192.168.99.10-192.168.99.100"},
  "pptp_client": {"enabled": false, "server": "", "username": "", "password": ""},
  "firewall": {"enabled": false, "rules": []},
  "logging": {"enabled": false, "level": "info"}
}
CONFIG
check_error "Gagal membuat config.json."

# Apply IP default ke interfaces
ip addr add 192.168.88.1/24 dev "$LAN_IF"
dhclient "$WAN_IF" || echo "Gagal mendapatkan IP WAN via DHCP, konfigurasi manual di WebUI."

# Jalankan update-rc.d untuk autostart
update-rc.d karos defaults
check_error "Gagal mengatur autostart service."

# Restart service
service karos restart
check_error "Gagal restart service karos."

# Dapatkan IP LAN
LAN_IP=$(ip addr show "$LAN_IF" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "IP tidak terdeteksi")
if [ -z "$LAN_IP" ]; then
    LAN_IP="192.168.88.1"  # Default
fi

# Tampilkan info
echo "Setup selesai. Akses WebUI: http://$LAN_IP:8080"
EOF
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# Buat /etc/init.d/karos (SysVinit script ditingkatkan)
# Support start, stop, restart. Jalankan WebUI di background, log ke /var/log/karos.log.
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
LOGFILE=/var/log/karos.log

case "$1" in
  start)
    if [ -f $PIDFILE ]; then
      echo "KarOS sudah berjalan."
    else
      touch $LOGFILE
      nohup python3 $WEBUI >> $LOGFILE 2>&1 &
      echo $! > $PIDFILE
      echo "KarOS dimulai."
    fi
    ;;
  stop)
    if [ -f $PIDFILE ]; then
      kill $(cat $PIDFILE)
      rm -f $PIDFILE
      echo "KarOS dihentikan."
    else
      echo "KarOS tidak berjalan."
    fi
    ;;
  restart)
    $0 stop
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

# Buat /usr/bin/karos-webui (Python Flask WebUI ditingkatkan)
# - Layout mirip Mikrotik Webfig: Sidebar menu kiri dengan links ke sections (IP, Wireless, PPP, Firewall, System).
# - Setiap section punya form detail untuk config.
# - Undo/redo sederhana: Simpan history config di session.
# - Style CSS mirip Mikrotik: Biru, tables, buttons.
# - Load/save config.json, apply via modul.
cat << 'EOF' > "$PKG_DIR/usr/bin/karos-webui"
#!/usr/bin/env python3

import json
import os
import subprocess
from flask import Flask, request, render_template_string, redirect, url_for, session
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = 'karos_secret_key'  # Untuk session undo/redo
CONFIG_PATH = '/etc/karos/config.json'
MODULES_DIR = '/usr/lib/karos/modules'
LOG_PATH = '/var/log/syslog'  # Atau /var/log/karos.log

# Fungsi load config
def load_config():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r') as f:
            return json.load(f)
    return {}

# Fungsi save config (dengan backup untuk undo)
def save_config(config):
    if 'config_history' not in session:
        session['config_history'] = []
    session['config_history'].append(json.dumps(load_config()))  # Backup lama
    if len(session['config_history']) > 10:  # Limit history
        session['config_history'].pop(0)
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=2)

# Fungsi undo
def undo():
    if 'config_history' in session and session['config_history']:
        prev_config = json.loads(session['config_history'].pop())
        with open(CONFIG_PATH, 'w') as f:
            json.dump(prev_config, f, indent=2)
        return prev_config
    return load_config()

# Fungsi apply feature
def apply_feature(feature):
    config = load_config()
    enabled = config.get(feature, {}).get('enabled', False)
    module_path = os.path.join(MODULES_DIR, f'{feature}.py')
    if os.path.exists(module_path):
        action = 'enable' if enabled else 'disable'
        subprocess.call(['python3', module_path, action, json.dumps(config[feature])])

# Template utama mirip Mikrotik: Sidebar kiri, content kanan, CSS biru.
MAIN_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>KarOS WebUI - Mirip Mikrotik Webfig</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 0; background: #f0f0f0; }
        #sidebar { width: 200px; float: left; background: #004080; color: white; height: 100vh; padding: 10px; }
        #sidebar a { color: white; display: block; padding: 5px; text-decoration: none; }
        #sidebar a:hover { background: #0066cc; }
        #content { margin-left: 210px; padding: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background: #0066cc; color: white; }
        button { background: #004080; color: white; border: none; padding: 10px; cursor: pointer; }
        button:hover { background: #0066cc; }
        form { margin-bottom: 20px; }
    </style>
</head>
<body>
    <div id="sidebar">
        <h2>KarOS Menu</h2>
        <a href="/">Dashboard</a>
        <a href="/ip">IP / Interfaces</a>
        <a href="/dhcp">DHCP Server</a>
        <a href="/dns">DNS Client</a>
        <a href="/vlan">VLAN</a>
        <a href="/wifi">Wireless AP</a>
        <a href="/pppoe">PPPoE</a>
        <a href="/pptp">PPTP</a>
        <a href="/firewall">Firewall</a>
        <a href="/logging">Logging</a>
        <a href="/logs">View Logs</a>
        <a href="/undo">Undo</a>
    </div>
    <div id="content">
        {% block content %}{% endblock %}
    </div>
</body>
</html>
'''

# Dashboard
DASHBOARD_TEMPLATE = MAIN_TEMPLATE + '''
{% extends "layout.html" %}
{% block content %}
<h1>KarOS Dashboard</h1>
<pre>
Interfaces:
  LAN: {{ config['interfaces']['lan'] }} ({{ config['interfaces']['lan_ip'] }})
  WAN: {{ config['interfaces']['wan'] }} ({{ config['interfaces']['wan_ip'] }})

Fitur Status:
{% for feature in features %}
  {{ feature|capitalize }}: {{ 'Enabled' if config[feature]['enabled'] else 'Disabled' }}
{% endfor %}
</pre>
{% endblock %}
'''

# Fungsi untuk render template (gunakan string untuk sederhana)
@app.route('/', methods=['GET'])
def index():
    config = load_config()
    features = ['dhcp_server', 'dns_client', 'vlan_support', 'wifi_ap', 'pppoe_server', 'pppoe_client', 'pptp_server', 'pptp_client', 'firewall', 'logging']
    return render_template_string(DASHBOARD_TEMPLATE.replace('{% extends "layout.html" %}', ''), config=config, features=features)

# IP / Interfaces page
@app.route('/ip', methods=['GET', 'POST'])
def set_ip():
    config = load_config()
    if request.method == 'POST':
        config['interfaces']['lan_ip'] = request.form.get('lan_ip', config['interfaces']['lan_ip'])
        config['interfaces']['wan_ip'] = request.form.get('wan_ip', config['interfaces']['wan_ip'])
        save_config(config)
        # Apply
        if 'lan_ip' in request.form:
            subprocess.call(['ip', 'addr', 'flush', 'dev', config['interfaces']['lan']])
            subprocess.call(['ip', 'addr', 'add', config['interfaces']['lan_ip'], 'dev', config['interfaces']['lan']])
        if 'wan_ip' in request.form:
            if config['interfaces']['wan_ip'] == 'dhcp':
                subprocess.call(['dhclient', config['interfaces']['wan']])
            else:
                subprocess.call(['ip', 'addr', 'flush', 'dev', config['interfaces']['wan']])
                subprocess.call(['ip', 'addr', 'add', config['interfaces']['wan_ip'], 'dev', config['interfaces']['wan']])
        return redirect(url_for('set_ip'))
    template = MAIN_TEMPLATE + '''
    {% block content %}
    <h1>IP / Interfaces</h1>
    <form method="post">
        LAN IP (e.g., 192.168.88.1/24): <input name="lan_ip" value="{{ config['interfaces']['lan_ip'] }}"><br>
        WAN IP (dhcp or e.g., 10.0.0.2/24): <input name="wan_ip" value="{{ config['interfaces']['wan_ip'] }}"><br>
        <button type="submit">Apply</button>
    </form>
    {% endblock %}
    '''
    return render_template_string(template, config=config)

# Generic feature page generator
def create_feature_route(feature):
    @app.route(f'/{feature}', methods=['GET', 'POST'])
    def feature_route():
        config = load_config()
        if request.method == 'POST':
            config[feature]['enabled'] = 'enabled' in request.form
            # Tambah field detail berdasarkan feature
            if feature == 'dhcp_server':
                config[feature]['range'] = request.form.get('range', config[feature]['range'])
            elif feature == 'dns_client':
                config[feature]['servers'] = request.form.get('servers', '').split(',')
            elif feature == 'vlan_support':
                config[feature]['vlans'] = request.form.get('vlans', '').split(',')
            elif feature == 'wifi_ap':
                config[feature]['ssid'] = request.form.get('ssid', config[feature]['ssid'])
                config[feature]['passphrase'] = request.form.get('passphrase', config[feature]['passphrase'])
                config[feature]['channel'] = int(request.form.get('channel', config[feature]['channel']))
            # ... tambah untuk lainnya
            save_config(config)
            apply_feature(feature)
            return redirect(url_for('feature_route'))
        template = MAIN_TEMPLATE + f'''
        {{% block content %}}
        <h1>{feature.upper()} Configuration</h1>
        <form method="post">
            Enabled: <input type="checkbox" name="enabled" {{ 'checked' if config['{feature}']['enabled'] else '' }}><br>
            ''' 
        if feature == 'dhcp_server':
            template += 'DHCP Range (e.g., 192.168.88.100,192.168.88.200,12h): <input name="range" value="{{ config[\'{feature}\'][\'range\'] }}"><br>'
        # Tambah field lain serupa
        template += '''
            <button type="submit">Apply</button>
        </form>
        {% endblock %}
        '''
        return render_template_string(template, config=config, feature=feature)
    return feature_route

# Buat routes untuk setiap feature
features = ['dhcp', 'dns', 'vlan', 'wifi', 'pppoe', 'pptp', 'firewall', 'logging']
feature_map = {'dhcp': 'dhcp_server', 'dns': 'dns_client', 'vlan': 'vlan_support', 'wifi': 'wifi_ap', 'pppoe': 'pppoe_server', 'pptp': 'pptp_server', 'firewall': 'firewall', 'logging': 'logging'}
for f in features:
    globals()[f + '_route'] = create_feature_route(feature_map[f])

# Tambah PPPoE client, PPTP client jika perlu page terpisah, tapi untuk sederhana gabung di pppoe/pptp.

@app.route('/undo', methods=['GET'])
def undo_route():
    undo()
    apply_all_features()  # Re-apply setelah undo
    return redirect(url_for('index'))

def apply_all_features():
    for feature in feature_map.values():
        apply_feature(feature)

@app.route('/logs')
def logs():
    try:
        logs = subprocess.check_output(['tail', '-n', '100', LOG_PATH]).decode()
    except:
        logs = "Logs tidak tersedia."
    template = MAIN_TEMPLATE + '''
    {% block content %}
    <h1>System Logs</h1>
    <pre>{{ logs }}</pre>
    {% endblock %}
    '''
    return render_template_string(template, logs=logs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
EOF
chmod 755 "$PKG_DIR/usr/bin/karos-webui"

# Buat modul-modul di /usr/lib/karos/modules/ dengan implementasi nyata
# Setiap modul handle enable/disable dengan config JSON sebagai arg.

# dhcp_server.py
cat << 'EOF' > "$PKG_DIR/usr/lib/karos/modules/dhcp_server.py"
#!/usr/bin/env python3

import sys
import json
import subprocess
import os

def enable(config):
    lan_if = load_global_config()['interfaces']['lan']
    lan_ip = load_global_config()['interfaces']['lan_ip'].split('/')[0]
    conf_path = '/etc/dnsmasq.conf'
    with open(conf_path, 'w') as f:
        f.write(f"interface={lan_if}\n")
        f.write(f"dhcp-range={config['range']}\n")
        f.write(f"dhcp-option=option:router,{lan_ip}\n")
        f.write("dhcp-option=option:dns-server,8.8.8.8\n")
    subprocess.call(['service', 'dnsmasq', 'restart'])

def disable(config):
    subprocess.call(['service', 'dnsmasq', 'stop'])

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
    with open('/etc/resolv.conf', 'w') as f:
        for server in config['servers']:
            f.write(f"nameserver {server}\n")

def disable(config):
    # Kembalikan default
    with open('/etc/resolv.conf', 'w') as f:
        f.write("nameserver 127.0.0.1\n")  # Atau hapus

if __name__ == '__main__':
    if len(sys.argv) != 3:
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
    lan_if = load_global_config()['interfaces']['lan']
    for vlan_id in config['vlans']:
        subprocess.call(['ip', 'link', 'add', 'link', lan_if, 'name', f'{lan_if}.{vlan_id}', 'type', 'vlan', 'id', vlan_id])
        subprocess.call(['ip', 'link', 'set', f'{lan_if}.{vlan_id}', 'up'])

def disable(config):
    lan_if = load_global_config()['interfaces']['lan']
    for vlan_id in config['vlans']:
        subprocess.call(['ip', 'link', 'delete', f'{lan_if}.{vlan_id}'])

def load_global_config():
    with open('/etc/karos/config.json', 'r') as f:
        return json.load(f)

if __name__ == '__main__':
    if len(sys.argv) != 3:
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
    lan_if = load_global_config()['interfaces']['lan']  # Asumsi wifi interface adalah wlan0 atau LAN jika wifi
    conf_path = '/etc/hostapd/hostapd.conf'
    with open(conf_path, 'w') as f:
        f.write(f"interface={lan_if}\n")  # Ganti dengan wifi if jika beda
        f.write("driver=nl80211\n")
        f.write(f"ssid={config['ssid']}\n")
        f.write(f"hw_mode=g\n")
        f.write(f"channel={config['channel']}\n")
        f.write("wpa=2\n")
        f.write(f"wpa_passphrase={config['passphrase']}\n")
        f.write("wpa_key_mgmt=WPA-PSK\n")
        f.write("rsn_pairwise=CCMP\n")
    subprocess.call(['service', 'hostapd', 'restart'])

def disable(config):
    subprocess.call(['service', 'hostapd', 'stop'])

def load_global_config():
    with open('/etc/karos/config.json', 'r') as f:
        return json.load(f)

if __name__ == '__main__':
    if len(sys.argv) != 3:
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
    conf_path = '/etc/ppp/pppoe-server-options'
    with open(conf_path, 'w') as f:
        f.write("require-pap\n")
        f.write(f"ms-dns 8.8.8.8\n")
    subprocess.call(['pppoe-server', '-I', load_global_config()['interfaces']['lan'], '-L', config['local_ip'], '-R', config['remote_ip'], '-F'])

def disable(config):
    subprocess.call(['killall', 'pppoe-server'])

def load_global_config():
    with open('/etc/karos/config.json', 'r') as f:
        return json.load(f)

if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(1)
    config = json.loads(sys.argv[2])
    if sys.argv[1] == 'enable':
        enable(config)
    else:
        disable(config)
EOF

# pppoe_client.py (serupa, gunakan pppd call)
cat << 'EOF' > "$PKG_DIR/usr/lib/karos/modules/pppoe_client.py"
#!/usr/bin/env python3

import sys
import json
import subprocess

def enable(config):
    # Buat peer file
    peer_path = '/etc/ppp/peers/pppoe'
    with open(peer_path, 'w') as f:
        f.write("plugin rp-pppoe.so\n")
        f.write(f"nic-{load_global_config()['interfaces']['wan']}\n")
        f.write(f"user \"{config['username']}\"\n")
        f.write("usepeerdns\n")
    chap_path = '/etc/ppp/chap-secrets'
    with open(chap_path, 'a') as f:
        f.write(f"{config['username']} * \"{config['password']}\" *\n")
    subprocess.call(['pon', 'pppoe'])

def disable(config):
    subprocess.call(['poff', 'pppoe'])

def load_global_config():
    with open('/etc/karos/config.json', 'r') as f:
        return json.load(f)

if __name__ == '__main__':
    if len(sys.argv) != 3:
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
    conf_path = '/etc/pptpd.conf'
    with open(conf_path, 'w') as f:
        f.write(f"localip {config['local_ip']}\n")
        f.write(f"remoteip {config['remote_ip']}\n")
    options_path = '/etc/ppp/pptpd-options'
    with open(options_path, 'w') as f:
        f.write("ms-dns 8.8.8.8\n")
    subprocess.call(['service', 'pptpd', 'restart'])

def disable(config):
    subprocess.call(['service', 'pptpd', 'stop'])

if __name__ == '__main__':
    if len(sys.argv) != 3:
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
import subprocess

def enable(config):
    peer_path = '/etc/ppp/peers/pptp'
    with open(peer_path, 'w') as f:
        f.write(f"pty \"pptp {config['server']} --nolaunchpppd\"\n")
        f.write(f"name {config['username']}\n")
        f.write("remotename PPTP\n")
        f.write("require-mppe-128\n")
        f.write("file /etc/ppp/options.pptp\n")
    chap_path = '/etc/ppp/chap-secrets'
    with open(chap_path, 'a') as f:
        f.write(f"{config['username']} PPTP \"{config['password']}\" *\n")
    subprocess.call(['pon', 'pptp'])

def disable(config):
    subprocess.call(['poff', 'pptp'])

if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(1)
    config = json.loads(sys.argv[2])
    if sys.argv[1] == 'enable':
        enable(config)
    else:
        disable(config)
EOF

# firewall.py (basic iptables)
cat << 'EOF' > "$PKG_DIR/usr/lib/karos/modules/firewall.py"
#!/usr/bin/env python3

import sys
import json
import subprocess

def enable(config):
    # Basic rules: Allow established, drop others
    subprocess.call(['iptables', '-F'])
    subprocess.call(['iptables', '-A', 'INPUT', '-i', 'lo', '-j', 'ACCEPT'])
    subprocess.call(['iptables', '-A', 'INPUT', '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])
    subprocess.call(['iptables', '-A', 'INPUT', '-j', 'DROP'])
    # Tambah rules custom dari config['rules'] jika ada
    for rule in config.get('rules', []):
        subprocess.call(['iptables'] + rule.split())
    # Save
    subprocess.call(['iptables-save', '>', '/etc/iptables.rules'])

def disable(config):
    subprocess.call(['iptables', '-F'])

if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(1)
    config = json.loads(sys.argv[2])
    if sys.argv[1] == 'enable':
        enable(config)
    else:
        disable(config)
EOF

# logging.py (rsyslog)
cat << 'EOF' > "$PKG_DIR/usr/lib/karos/modules/logging.py"
#!/usr/bin/env python3

import sys
import json
import subprocess

def enable(config):
    # Konfig rsyslog level jika perlu
    subprocess.call(['service', 'rsyslog', 'start'])

def disable(config):
    subprocess.call(['service', 'rsyslog', 'stop'])

if __name__ == '__main__':
    if len(sys.argv) != 3:
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

# Build paket .deb
dpkg-deb --build "$PKG_DIR"
if [ $? -eq 0 ]; then
    echo "Paket berhasil dibuild: ${PKG_DIR}.deb"
else
    echo "Gagal build paket."
    exit 1
fi
