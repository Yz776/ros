#!/bin/bash
set -e
PKG="roslike"
VER="1.0-1"
WORK="${PKG}_${VER}"
echo ">> Building ${PKG} package in ${WORK} ..."

# cleanup
rm -rf "$WORK"
mkdir -p "$WORK/DEBIAN"
mkdir -p "$WORK/usr/bin"
mkdir -p "$WORK/usr/lib/roslike/modules"
mkdir -p "$WORK/lib/systemd/system"
mkdir -p "$WORK/etc/profile.d"
mkdir -p "$WORK/etc/roslike/config"
mkdir -p "$WORK/var/log/roslike"

# -------------------------
# control
# -------------------------
cat > "$WORK/DEBIAN/control" <<EOF
Package: $PKG
Version: $VER
Section: net
Priority: optional
Architecture: all
Depends: python3-flask, iproute2, iptables, dnsmasq, hostapd, ppp, pptpd, squid, postfix
Maintainer: Admin <admin@example.com>
Description: RouterOS-like system (roslike) - modular router features CLI+WebUI
EOF

# -------------------------
# postinst (wizard) - no apt installs here
# -------------------------
cat > "$WORK/DEBIAN/postinst" <<'POSTINST'
#!/bin/bash
set -e
echo ">> roslike post-install wizard"
mkdir -p /etc/roslike/config /var/log/roslike

if [ ! -f /etc/roslike/config/.initialized ]; then
  echo "Interfaces available:"
  ip -o link show | awk -F': ' '{print NR ") " $2}'
  read -p "Pilih interface untuk WAN: " WAN
  read -p "Pilih interface untuk LAN: " LAN
  echo -n "Masukkan password baru untuk root: "
  read -s PW
  echo
  echo "root:$PW" | chpasswd || true
  cat > /etc/roslike/config/network.conf <<EOC
WAN=$WAN
LAN=$LAN
EOC
  if ! id rosadmin >/dev/null 2>&1; then
    useradd -m -s /usr/bin/roslike rosadmin || true
    echo "rosadmin:roslike" | chpasswd || true
    echo "rosadmin user created with password 'roslike'"
  fi
  touch /etc/roslike/config/.initialized
  echo "Initial setup done."
fi

# enable webui service if systemd
if [ "$(ps -p 1 -o comm=)" = "systemd" ]; then
  systemctl daemon-reload || true
  systemctl enable roslike-webui.service || true
  systemctl restart roslike-webui.service || true
else
  update-rc.d roslike-webui defaults || true
  service roslike-webui restart || true
fi

echo "roslike installed. SSH as root or rosadmin will drop into roslike CLI."
POSTINST
chmod 755 "$WORK/DEBIAN/postinst"

# -------------------------
# postrm - cleanup
# -------------------------
cat > "$WORK/DEBIAN/postrm" <<'POSTRM'
#!/bin/bash
set -e
# stop service
if [ "$(ps -p 1 -o comm=)" = "systemd" ]; then
  systemctl stop roslike-webui.service || true
  systemctl disable roslike-webui.service || true
fi
rm -rf /etc/roslike
POSTRM
chmod 755 "$WORK/DEBIAN/postrm"

# -------------------------
# systemd unit for WebUI
# -------------------------
cat > "$WORK/lib/systemd/system/roslike-webui.service" <<EOF
[Unit]
Description=roslike WebUI
After=network.target

[Service]
ExecStart=/usr/bin/roslike-webui
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# -------------------------
# profile.d launcher for ssh login -> CLI for root & rosadmin
# -------------------------
cat > "$WORK/etc/profile.d/roslike.sh" <<'EOF'
#!/bin/bash
# Only exec CLI for root and rosadmin interactive logins
# avoid running for non-login shells
if [ -n "$PS1" ] && { [ "$USER" = "root" ] || [ "$USER" = "rosadmin" ]; } ; then
  if [ -x /usr/bin/roslike ]; then
    # avoid recursion
    # if parent shell already roslike, let it
    case "$SHELL" in */roslike) exit 0 ;; esac
    exec /usr/bin/roslike
  fi
fi
EOF
chmod 755 "$WORK/etc/profile.d/roslike.sh"

# -------------------------
# Module: ip (real actions)
# /usr/lib/roslike/modules/ip.sh
# -------------------------
cat > "$WORK/usr/lib/roslike/modules/ip.sh" <<'EOF'
#!/bin/bash
# ip module: address add/del/print, route print/add/del
ACTION=$1; shift
case "$ACTION" in
  address)
    SUB=$1; shift
    case "$SUB" in
      add)
        # usage: ip.sh address add 192.168.10.1/24 dev eth0
        ip addr add "$@" && echo "OK" || echo "FAIL"
        ;;
      remove|del)
        ip addr del "$@" && echo "OK" || echo "FAIL"
        ;;
      print)
        ip -o addr show
        ;;
      *)
        echo "usage: ip address {add|remove|print} ..."
        ;;
    esac
    ;;
  route)
    SUB=$1; shift
    case "$SUB" in
      add) ip route add "$@" ;;
      del|remove) ip route del "$@" ;;
      print) ip route show ;;
      *) echo "usage: ip route {add|del|print} ..." ;;
    esac
    ;;
  link)
    SUB=$1; shift
    case "$SUB" in
      show|print) ip -o link show ;;
      up) ip link set "$1" up ;;
      down) ip link set "$1" down ;;
      *)
        echo "usage: ip link {show|up|down} ..."
        ;;
    esac
    ;;
  *)
    echo "ip module. usage: ip.sh {address|route|link} ..."
    ;;
esac
EOF
chmod 755 "$WORK/usr/lib/roslike/modules/ip.sh"

# -------------------------
# Module: dhcp (dnsmasq controller)
# -------------------------
cat > "$WORK/usr/lib/roslike/modules/dhcp.sh" <<'EOF'
#!/bin/bash
# dhcp.sh start|stop|status|config
CMD=$1; shift
CONF=/etc/roslike/config/dnsmasq.conf
case "$CMD" in
  start)
    if [ -f "$CONF" ]; then
      cp "$CONF" /etc/dnsmasq.d/roslike.conf
    else
      # default simple DHCP on LAN from ip config
      . /etc/roslike/config/network.conf 2>/dev/null || true
      if [ -n "$LAN" ]; then
        cat > /etc/dnsmasq.d/roslike.conf <<EOM
interface=$LAN
dhcp-range=192.168.77.50,192.168.77.150,12h
EOM
      fi
    fi
    systemctl restart dnsmasq 2>/dev/null || service dnsmasq restart 2>/dev/null
    ;;
  stop)
    rm -f /etc/dnsmasq.d/roslike.conf
    systemctl restart dnsmasq 2>/dev/null || service dnsmasq restart 2>/dev/null
    ;;
  status)
    systemctl status dnsmasq 2>/dev/null || service dnsmasq status 2>/dev/null
    ;;
  config)
    # writes raw dnsmasq config from stdin
    cat - > "$CONF"
    ;;
  *)
    echo "Usage: dhcp.sh {start|stop|status|config}"
    ;;
esac
EOF
chmod 755 "$WORK/usr/lib/roslike/modules/dhcp.sh"

# -------------------------
# Module: dns (client)
# -------------------------
cat > "$WORK/usr/lib/roslike/modules/dns.sh" <<'EOF'
#!/bin/bash
# dns.sh set <ip1> [ip2] | print
CMD=$1; shift
case "$CMD" in
  set)
    echo "nameserver $1" > /etc/resolv.conf
    if [ -n "$2" ]; then echo "nameserver $2" >> /etc/resolv.conf; fi
    echo "OK"
    ;;
  print)
    cat /etc/resolv.conf
    ;;
  *)
    echo "dns.sh set <ip1> [ip2] | print"
    ;;
esac
EOF
chmod 755 "$WORK/usr/lib/roslike/modules/dns.sh"

# -------------------------
# Module: firewall (iptables simple)
# -------------------------
cat > "$WORK/usr/lib/roslike/modules/firewall.sh" <<'EOF'
#!/bin/bash
CMD=$1; shift
case "$CMD" in
  nat-enable)
    # basic NAT from LAN -> WAN (reads /etc/roslike/config/network.conf)
    . /etc/roslike/config/network.conf 2>/dev/null || true
    if [ -n "$WAN" ] && [ -n "$LAN" ]; then
      iptables -t nat -A POSTROUTING -o "$WAN" -j MASQUERADE
      iptables -A FORWARD -i "$LAN" -o "$WAN" -j ACCEPT
      iptables -A FORWARD -o "$LAN" -m state --state RELATED,ESTABLISHED -j ACCEPT
      echo "NAT enabled"
    else
      echo "WAN/LAN not configured"
    fi
    ;;
  nat-disable)
    . /etc/roslike/config/network.conf 2>/dev/null || true
    if [ -n "$WAN" ] && [ -n "$LAN" ]; then
      iptables -t nat -D POSTROUTING -o "$WAN" -j MASQUERADE 2>/dev/null || true
      iptables -D FORWARD -i "$LAN" -o "$WAN" -j ACCEPT 2>/dev/null || true
      iptables -D FORWARD -o "$LAN" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || true
      echo "NAT disabled"
    else
      echo "WAN/LAN not configured"
    fi
    ;;
  save)
    iptables-save > /etc/roslike/firewall.rules
    echo "Saved"
    ;;
  restore)
    if [ -f /etc/roslike/firewall.rules ]; then
      iptables-restore < /etc/roslike/firewall.rules
      echo "Restored"
    else
      echo "No saved rules"
    fi
    ;;
  *)
    echo "firewall.sh {nat-enable|nat-disable|save|restore}"
    ;;
esac
EOF
chmod 755 "$WORK/usr/lib/roslike/modules/firewall.sh"

# -------------------------
# Module: vlan
# -------------------------
cat > "$WORK/usr/lib/roslike/modules/vlan.sh" <<'EOF'
#!/bin/bash
# vlan.sh add <parent> <id> | del <vlan_if> | show
CMD=$1; shift
case "$CMD" in
  add)
    P=$1; ID=$2
    ip link add link "$P" name "${P}.${ID}" type vlan id "$ID"
    ip link set "${P}.${ID}" up
    echo "created ${P}.${ID}"
    ;;
  del)
    ip link delete "$1" || echo "fail"
    ;;
  show|print)
    ip -d link show type vlan
    ;;
  *)
    echo "vlan.sh add <parent> <id> | del <vlan_if> | show"
    ;;
esac
EOF
chmod 755 "$WORK/usr/lib/roslike/modules/vlan.sh"

# -------------------------
# Module: wlan (hostapd-based basic AP)
# -------------------------
cat > "$WORK/usr/lib/roslike/modules/wlan.sh" <<'EOF'
#!/bin/bash
CMD=$1; shift
CONF=/etc/roslike/hostapd_roslike.conf
case "$CMD" in
  ap-create)
    IFACE=$1; SSID=$2; PASS=$3
    cat > "$CONF" <<EOM
interface=$IFACE
driver=nl80211
ssid=$SSID
hw_mode=g
channel=6
wpa=2
wpa_passphrase=$PASS
EOM
    systemctl restart hostapd 2>/dev/null || service hostapd restart 2>/dev/null
    echo "ap created on $IFACE"
    ;;
  ap-destroy)
    rm -f "$CONF"
    systemctl restart hostapd 2>/dev/null || service hostapd restart 2>/dev/null
    echo "ap removed"
    ;;
  status)
    systemctl status hostapd 2>/dev/null || service hostapd status 2>/dev/null
    ;;
  *)
    echo "wlan.sh ap-create <iface> <ssid> <pass> | ap-destroy | status"
    ;;
esac
EOF
chmod 755 "$WORK/usr/lib/roslike/modules/wlan.sh"

# -------------------------
# Module: pppoe (client template)
# -------------------------
cat > "$WORK/usr/lib/roslike/modules/pppoe.sh" <<'EOF'
#!/bin/bash
# pppoe.sh client add <iface> <user> <pass> | remove <iface> | status
CMD=$1; shift
case "$CMD" in
  client)
    SUB=$1; shift
    case "$SUB" in
      add)
        IFACE=$1; USER=$2; PASS=$3
        # Create pppd options file
        cat > /etc/ppp/peers/roslike-$IFACE <<EOM
noauth
persist
mtu 1492
mru 1492
plugin rp-pppoe.so $IFACE
user "$USER"
EOM
        # put password
        echo "$USER:$PASS" > /etc/ppp/chap-secrets
        pppd call roslike-$IFACE &
        echo "pppoe client started on $IFACE"
        ;;
      remove)
        echo "pppoe remove: manual cleanup needed or kill pppd"
        ;;
      status)
        pppd status 2>/dev/null || echo "no pppd status"
        ;;
    esac
    ;;
  server)
    case "$1" in
      enable) systemctl restart pptpd 2>/dev/null || service pptpd restart ;; 
      disable) systemctl stop pptpd 2>/dev/null || service pptpd stop ;;
      *) echo "pppoe server: enable|disable" ;;
    esac
    ;;
  *)
    echo "pppoe.sh client add|remove|status  OR pppoe.sh server enable|disable"
    ;;
esac
EOF
chmod 755 "$WORK/usr/lib/roslike/modules/pppoe.sh"

# -------------------------
# Module: pptp (basic control)
# -------------------------
cat > "$WORK/usr/lib/roslike/modules/pptp.sh" <<'EOF'
#!/bin/bash
CMD=$1; shift
case "$CMD" in
  server)
    case "$1" in
      start) systemctl restart pptpd 2>/dev/null || service pptpd restart ;;
      stop) systemctl stop pptpd 2>/dev/null || service pptpd stop ;;
      status) systemctl status pptpd 2>/dev/null || service pptpd status ;;
      *) echo "pptp server {start|stop|status}" ;;
    esac
    ;;
  *)
    echo "pptp.sh server {start|stop|status}"
    ;;
esac
EOF
chmod 755 "$WORK/usr/lib/roslike/modules/pptp.sh"

# -------------------------
# Module: proxy (squid)
# -------------------------
cat > "$WORK/usr/lib/roslike/modules/proxy.sh" <<'EOF'
#!/bin/bash
CMD=$1; shift
case "$CMD" in
  start) systemctl restart squid 2>/dev/null || service squid restart ;;
  stop) systemctl stop squid 2>/dev/null || service squid stop ;;
  status) systemctl status squid 2>/dev/null || service squid status ;;
  *) echo "proxy.sh start|stop|status" ;;
esac
EOF
chmod 755 "$WORK/usr/lib/roslike/modules/proxy.sh"

# -------------------------
# Module: mail (postfix/dovecot helpers)
# -------------------------
cat > "$WORK/usr/lib/roslike/modules/mail.sh" <<'EOF'
#!/bin/bash
CMD=$1; shift
case "$CMD" in
  start) systemctl restart postfix 2>/dev/null || service postfix restart ;;
  stop) systemctl stop postfix 2>/dev/null || service postfix stop ;;
  status) systemctl status postfix 2>/dev/null || service postfix status ;;
  *) echo "mail.sh start|stop|status" ;;
esac
EOF
chmod 755 "$WORK/usr/lib/roslike/modules/mail.sh"

# -------------------------
# CLI dispatcher (Python) - full MikroTik style with submenu & tab-complete
# -------------------------
cat > "$WORK/usr/bin/roslike" <<'PY'
#!/usr/bin/env python3
import readline, shlex, subprocess, os, sys
PROMPT="[roslike]"
current=[]
# available modules map: command -> script path
MODULES = {
  "ip": "/usr/lib/roslike/modules/ip.sh",
  "dhcp": "/usr/lib/roslike/modules/dhcp.sh",
  "dns": "/usr/lib/roslike/modules/dns.sh",
  "firewall": "/usr/lib/roslike/modules/firewall.sh",
  "vlan": "/usr/lib/roslike/modules/vlan.sh",
  "wlan": "/usr/lib/roslike/modules/wlan.sh",
  "pppoe": "/usr/lib/roslike/modules/pppoe.sh",
  "pptp": "/usr/lib/roslike/modules/pptp.sh",
  "proxy": "/usr/lib/roslike/modules/proxy.sh",
  "mail": "/usr/lib/roslike/modules/mail.sh"
}
def get_ifaces():
    try:
        out = subprocess.check_output(["ip","-o","link","show"], text=True)
        return [line.split(": ")[1].split("@")[0] for line in out.splitlines()]
    except:
        return []
def complete(text,state):
    buf=readline.get_line_buffer()
    toks=shlex.split(buf) if buf.strip() else []
    opts=[]
    if not toks:
        opts=list(MODULES.keys())+["system","quit","exit","help"]
    elif len(toks)==1:
        opts=[c for c in list(MODULES.keys())+["system","help"] if c.startswith(toks[0])]
    else:
        if toks[0]=="ip" and len(toks)==2:
            opts=[p for p in ["address","route","link"] if p.startswith(toks[1])]
        elif toks[0]=="ip" and toks[1]=="address" and len(toks)==3:
            opts=[p for p in ["print","add","remove"] if p.startswith(toks[2])]
        elif toks[0]=="vlan" and len(toks)==2:
            opts=[p for p in ["add","del","show"] if p.startswith(toks[1])]
        elif toks[0]=="interface" or (toks[0] in ("ip","vlan") and toks[-1]=="set"):
            opts=[i for i in get_ifaces() if i.startswith(text)]
    try:
        return opts[state]
    except:
        return None
readline.parse_and_bind("tab: complete")
readline.set_completer(complete)
def run_line(line):
    if not line.strip():
        return
    toks=shlex.split(line)
    if toks[0] in ("quit","exit"):
        sys.exit(0)
    if toks[0]=="help":
        print("Available:",",".join(list(MODULES.keys())+["system","quit","exit"]))
        return
    if toks[0]=="system":
        if len(toks)>1 and toks[1]=="shell":
            os.system("/bin/bash")
            return
        elif len(toks)>1 and toks[1]=="reboot":
            os.system("reboot")
            return
        elif len(toks)>1 and toks[1]=="shutdown":
            os.system("shutdown now")
            return
        else:
            print("system commands: shell,reboot,shutdown")
            return
    # dispatch module
    if toks[0] in MODULES:
        script=MODULES[toks[0]]
        # convert tokens to args for script: call script with tokens[1]...
        try:
            p=subprocess.run([script]+toks[1:], check=False, text=True, capture_output=False)
        except Exception as e:
            print("Error calling module:",e)
        return
    # special ip shorthand
    if toks[0]=="interface":
        if len(toks)>1 and toks[1]=="print":
            os.system("ip -o link show")
            return
    print("Unknown command")
def main():
    while True:
        try:
            path="/".join(current)
            prompt = f"{PROMPT}/{path}> " if path else f"{PROMPT}> "
            line=input(prompt)
            run_line(line)
        except (EOFError,KeyboardInterrupt):
            print("\nBye")
            break
if __name__=="__main__":
    main()
PY
chmod 755 "$WORK/usr/bin/roslike"

# -------------------------
# WebUI (Flask) calling modules via subprocess
# -------------------------
cat > "$WORK/usr/bin/roslike-webui" <<'PY'
#!/usr/bin/env python3
from flask import Flask, request, jsonify, render_template_string
import subprocess, shlex, os
app=Flask(__name__)
TEMPLATE='''<!doctype html><html><head><meta charset="utf-8"><title>roslike</title></head><body>
<h1>roslike WebUI</h1>
<form method="post" action="/api/ip/address/add">
IP add: <input name="args" placeholder="192.168.88.1/24 dev eth0"/><button type="submit">Add</button></form>
<hr>
<form method="post" action="/api/dhcp/start">
<button type="submit">Start DHCP</button></form>
<hr>
<a href="/status">status</a>
</body></html>'''
@app.route("/")
def index(): return render_template_string(TEMPLATE)
@app.route("/status")
def status():
    out={}
    out['ip']=subprocess.getoutput("ip -o addr show")
    out['dns']=open("/etc/resolv.conf").read() if os.path.exists("/etc/resolv.conf") else ""
    return "<pre>"+out['ip']+"\n\n"+out['dns']+"</pre>"
@app.route("/api/ip/address/add", methods=["POST"])
def ip_add():
    args=request.form.get("args","")
    cmd=f"/usr/lib/roslike/modules/ip.sh address add {shlex.quote(args)}"
    # split into words for script; but ip.sh expects tokens; we pass as single arg (it handles)
    r=subprocess.run(cmd,shell=True,capture_output=True,text=True)
    return jsonify({"rc":r.returncode,"out":r.stdout,"err":r.stderr})
@app.route("/api/dhcp/start", methods=["POST"])
def dhcp_start():
    r=subprocess.run(["/usr/lib/roslike/modules/dhcp.sh","start"],capture_output=True,text=True)
    return jsonify({"rc":r.returncode,"out":r.stdout,"err":r.stderr})
if __name__=="__main__":
    app.run(host="0.0.0.0", port=8080)
PY
chmod 755 "$WORK/usr/bin/roslike-webui"

# -------------------------
# finalize build
# -------------------------
dpkg-deb --build "$WORK"
echo "Built: ${WORK}.deb"
