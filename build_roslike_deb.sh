#!/bin/bash
set -e

PKG=roslike
VER=1.0
REL=1
BUILD_DIR=${PKG}_${VER}-${REL}

echo ">> Membuat struktur paket $BUILD_DIR"
rm -rf $BUILD_DIR
mkdir -p $BUILD_DIR/DEBIAN
mkdir -p $BUILD_DIR/usr/bin
mkdir -p $BUILD_DIR/lib/systemd/system
mkdir -p $BUILD_DIR/etc/init.d

# --- control file ---
cat > $BUILD_DIR/DEBIAN/control <<EOF
Package: $PKG
Version: $VER-$REL
Section: net
Priority: optional
Architecture: all
Depends: python3, python3-flask, iproute2, hostapd, dnsmasq, ppp, pptpd, mariadb-server
Maintainer: roslike <admin@roslike.local>
Description: RouterOS-like system for Debian/Ubuntu
EOF

# --- postinst ---
cat > $BUILD_DIR/DEBIAN/postinst <<'EOF'
#!/bin/bash
set -e

echo ">> [roslike] Setup awal"

# ganti shell root → roslike
if ! grep -q "/usr/bin/roslike" /etc/passwd; then
    chsh -s /usr/bin/roslike root || true
fi

# systemctl atau service
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable roslike || true
    systemctl restart roslike || true
else
    update-rc.d roslike defaults || true
    service roslike restart || true
fi

echo ">> RouterOS-like system terpasang."
echo "   Akses WebUI: http://<LAN_IP>:8080"
EOF
chmod 755 $BUILD_DIR/DEBIAN/postinst

# --- CLI binary ---
cat > $BUILD_DIR/usr/bin/roslike <<'EOF'
#!/usr/bin/env python3
import readline, shlex, subprocess, os, sys

PROMPT = "[roslike]"
current_path = []

COMMANDS = {
    "interface": {
        "print": None,
        "set": "<iface>",
        "enable": "<iface>",
        "disable": "<iface>"
    },
    "ip": {
        "address": {
            "print": None,
            "add": "<ip>/<mask> dev <iface>",
            "remove": "<ip>/<mask> dev <iface>"
        },
        "dns": {
            "set": "server=<ip>",
            "print": None
        },
        "dhcp-client": {
            "add": "iface=<iface>",
            "remove": "<iface>",
            "print": None
        }
    },
    "pppoe": {
        "client": {
            "add": "iface=<iface> user=<user> pass=<pass>",
            "print": None
        },
        "server": {
            "enable": None,
            "disable": None,
            "print": None
        }
    },
    "system": {
        "identity": {
            "set": "name=<hostname>",
            "print": None
        },
        "reboot": None,
        "shutdown": None,
        "shell": None
    }
}

def get_interfaces():
    try:
        result = subprocess.check_output(["ip", "-o", "link", "show"], text=True)
        return [line.split(": ")[1].split("@")[0] for line in result.splitlines()]
    except Exception:
        return []

def completer(text, state):
    buffer = readline.get_line_buffer().strip()
    tokens = shlex.split(buffer)
    node = COMMANDS
    for p in current_path:
        if isinstance(node, dict) and p in node:
            node = node[p]

    options = []
    if isinstance(node, dict):
        options = [c for c in node.keys() if c.startswith(text)]
    elif current_path == ["interface", "set"] or current_path == ["interface", "enable"] or current_path == ["interface", "disable"]:
        options = [i for i in get_interfaces() if i.startswith(text)]
    try:
        return options[state]
    except IndexError:
        return None

readline.parse_and_bind("tab: complete")
readline.set_completer(completer)

def run_cmd(tokens):
    global current_path
    if not tokens:
        return
    cmd = tokens[0]

    if cmd in ("quit", "exit"):
        if not current_path:
            print("Bye")
            sys.exit(0)
        else:
            current_path = []
            return
    if cmd == "..":
        if current_path:
            current_path.pop()
        return

    node = COMMANDS
    for p in current_path:
        node = node[p]

    if cmd in node and isinstance(node[cmd], dict):
        current_path.append(cmd)
        return
    elif cmd in node:
        action = current_path + [cmd]
        if action == ["interface", "print"]:
            subprocess.run(["ip", "-o", "link", "show"])
        elif action == ["ip", "address", "print"]:
            subprocess.run(["ip", "-o", "addr", "show"])
        elif action == ["system", "identity", "print"]:
            subprocess.run(["hostnamectl"])
        elif action == ["system", "shell"]:
            os.system("/bin/bash")
        elif action == ["system", "reboot"]:
            os.system("reboot")
        elif action == ["system", "shutdown"]:
            os.system("shutdown now")
        else:
            print("not implemented yet")
    else:
        print("unknown command")

def main():
    global current_path
    while True:
        try:
            path_str = "/".join(current_path)
            prompt = f"{PROMPT}/{path_str}> " if path_str else f"{PROMPT}> "
            line = input(prompt)
            tokens = shlex.split(line)
            run_cmd(tokens)
        except (EOFError, KeyboardInterrupt):
            print("\nBye")
            break

if __name__ == "__main__":
    main()
EOF
chmod 755 $BUILD_DIR/usr/bin/roslike

# --- systemd service ---
cat > $BUILD_DIR/lib/systemd/system/roslike.service <<EOF
[Unit]
Description=RouterOS-like WebUI
After=network.target

[Service]
ExecStart=/usr/bin/roslike
Restart=always
User=root

[Install]
WantedBy=multi-user.target
EOF

# --- sysvinit fallback ---
cat > $BUILD_DIR/etc/init.d/roslike <<'EOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides: roslike
# Required-Start: $network
# Required-Stop: $network
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: RouterOS-like CLI
### END INIT INFO

case "$1" in
  start) /usr/bin/roslike & ;;
  stop) pkill -f roslike ;;
  restart) pkill -f roslike; /usr/bin/roslike & ;;
  *) echo "Usage: /etc/init.d/roslike {start|stop|restart}"; exit 1 ;;
esac
exit 0
EOF
chmod 755 $BUILD_DIR/etc/init.d/roslike

# --- Build .deb ---
echo ">> Membuat paket .deb ..."
dpkg-deb --build $BUILD_DIR
echo ">> Selesai: $(pwd)/${BUILD_DIR}.deb"
