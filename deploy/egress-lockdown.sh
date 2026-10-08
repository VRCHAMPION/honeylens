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
# Run as root on the VM BEFORE starting the Compose stack. The script creates
# DOCKER-USER if it does not exist yet (Docker keeps an existing chain), and
# the rules match the configured subnet/interface, so they block NEW egress as
# soon as Cowrie's bridge comes up.
#   sudo sh deploy/egress-lockdown.sh
# Make it survive reboots: install deploy/honeylens-egress-lockdown.service
# (runs this script before docker.service on every boot; see DEPLOY_CLOUD.md
# step 9). Re-running is safe: old copies of the rules are removed first.
#
# IPv6: cowrie_net has no IPv6 subnet, so Cowrie has no IPv6 address. The same
# rules are still added with ip6tables (matched on the bridge interface) when
# ip6tables is available, so enabling IPv6 later cannot silently open egress.
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
# 4) the same for IPv6, matched on the bridge (there is no IPv6 subnet to match).
if command -v ip6tables >/dev/null 2>&1 && ip6tables -L INPUT -n >/dev/null 2>&1; then
  ip6tables -N DOCKER-USER 2>/dev/null || true
  while ip6tables -D DOCKER-USER -i "$BRIDGE" -m conntrack --ctstate NEW -j DROP 2>/dev/null; do :; done
  while ip6tables -D DOCKER-USER -i "$BRIDGE" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN 2>/dev/null; do :; done
  while ip6tables -D INPUT -i "$BRIDGE" -m conntrack --ctstate NEW -j DROP 2>/dev/null; do :; done
  ip6tables -I DOCKER-USER 1 -i "$BRIDGE" -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN
  ip6tables -I DOCKER-USER 2 -i "$BRIDGE" -m conntrack --ctstate NEW -j DROP
  ip6tables -I INPUT 1 -i "$BRIDGE" -m conntrack --ctstate NEW -j DROP
  echo "IPv6: NEW connections from $BRIDGE dropped (DOCKER-USER + INPUT)."
else
  echo "IPv6: ip6tables not available; skipped (cowrie_net has no IPv6 subnet)."
fi
echo "Egress from $SUBNET blocked. Current DOCKER-USER chain:"
iptables -L DOCKER-USER -n -v --line-numbers
iptables -L INPUT -n -v --line-numbers | head -5
echo "Now start the Compose stack, then verify (local targets only): sudo sh deploy/verify-egress.sh  -> must print PASS"
