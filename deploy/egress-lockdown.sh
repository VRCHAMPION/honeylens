#!/bin/sh
# Block ALL outbound (egress) traffic from the Cowrie container network.
# Not yet tested on a real cloud VM (checked with ShellCheck 0.10.0).
#
# What: Docker evaluates the DOCKER-USER iptables chain before its own rules for
# traffic forwarded to/from containers. We allow replies to connections that
# attackers opened (ESTABLISHED,RELATED) and drop every NEW connection that
# Cowrie itself tries to open. So even if an attacker tricks Cowrie, it cannot
# download malware or attack someone else ("no pivoting").
#
# Run as root on the VM BEFORE starting the Compose stack. Docker must already
# be running so DOCKER-USER exists; rules match the configured subnet/interface
# and block NEW egress as soon as Cowrie's bridge comes up.
#   sudo sh deploy/egress-lockdown.sh
# Make it permanent: sudo apt install iptables-persistent && sudo netfilter-persistent save
set -eu
SUBNET="172.31.250.0/24"     # must match docker-compose.cloud.yml (cowrie_net)
BRIDGE="hl-cowrie0"
iptables -N DOCKER-USER 2>/dev/null || true
# Remove old copies of our rules (idempotent re-run).
while iptables -D DOCKER-USER -s "$SUBNET" -m conntrack --ctstate NEW -j DROP 2>/dev/null; do :; done
while iptables -D DOCKER-USER -i "$BRIDGE" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null; do :; done
while iptables -D INPUT -i "$BRIDGE" -m conntrack --ctstate NEW -j DROP 2>/dev/null; do :; done
# 1) replies to attacker-initiated connections are fine
iptables -I DOCKER-USER 1 -i "$BRIDGE" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
# 2) anything NEW that Cowrie starts is dropped (internet, other containers, the host's LAN)
iptables -I DOCKER-USER 2 -s "$SUBNET" -m conntrack --ctstate NEW -j DROP
# 3) Cowrie may not open connections to the VM itself either (e.g. the real sshd, cloud metadata
#    via the host). DOCKER-USER only sees FORWARDED traffic, so this needs the INPUT chain.
iptables -I INPUT 1 -i "$BRIDGE" -m conntrack --ctstate NEW -j DROP
echo "Egress from $SUBNET blocked. Current DOCKER-USER chain:"
iptables -L DOCKER-USER -n -v --line-numbers
iptables -L INPUT -n -v --line-numbers | head -5
echo "Now start the Compose stack, then verify (local targets only): sudo sh deploy/verify-egress.sh  -> must print PASS"
