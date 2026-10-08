#!/bin/sh
# Prove the egress lockdown WITHOUT sending traffic to any real Internet service.
#
# What it does (all targets are on this machine and controlled by this script):
#   1. creates a throwaway network namespace "hl-egress" joined to the host by a veth pair,
#      addressed from 198.18.0.0/15 (RFC 2544 benchmarking range, never used on the Internet),
#      and starts a listener in it. To the host it looks like a router hop away, so
#      Cowrie -> 198.18.0.2 is FORWARDED and NAT-ed exactly like Internet traffic;
#   2. starts a throwaway listener on the host at the Cowrie bridge gateway (172.31.250.1),
#      which covers traffic from Cowrie to the VM itself (INPUT chain);
#   3. from inside the Cowrie container, tries to open a TCP connection to both;
#   4. reads the packet counters of the two DROP rules before and after.
# PASS = both connections fail AND both DROP counters went up (so it was OUR rule that
# blocked them, not a missing route).
#
# Usage (on the VM, from the honeylens folder, stack running with the cloud override):
#   sudo sh deploy/verify-egress.sh                 # after deploy/egress-lockdown.sh
set -eu
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.cloud.yml"
SUBNET="172.31.250.0/24"
BRIDGE="hl-cowrie0"
GATEWAY="172.31.250.1"
PORT=18080
NS=hl-egress
HOST_END=198.18.0.1
TARGET_IP=198.18.0.2            # RFC 2544 test address inside our own namespace
PY=/cowrie/cowrie-env/bin/python3

# shellcheck disable=SC2317  # called through the trap below
cleanup() {
  if [ -n "${NS_PID:-}" ]; then kill "$NS_PID" 2>/dev/null || true; fi
  ip netns del "$NS" 2>/dev/null || true
  ip link del hl-eg0 2>/dev/null || true
  if [ -n "${HOST_PID:-}" ]; then kill "$HOST_PID" 2>/dev/null || true; fi
}
trap cleanup EXIT INT TERM

counter() {   # packets matched by a rule, or 0 if the rule is missing
  iptables -L "$1" -v -n -x 2>/dev/null | awk -v m="$2" '$0 ~ m && /DROP/ {print $1; f=1; exit} END {if (!f) print 0}'
}

cleanup
ip netns add "$NS"
ip link add hl-eg0 type veth peer name hl-eg1
ip link set hl-eg1 netns "$NS"
ip addr add "$HOST_END/30" dev hl-eg0 && ip link set hl-eg0 up
ip netns exec "$NS" ip addr add "$TARGET_IP/30" dev hl-eg1
ip netns exec "$NS" ip link set hl-eg1 up
ip netns exec "$NS" ip link set lo up
ip netns exec "$NS" ip route add default via "$HOST_END"
(cd / && exec ip netns exec "$NS" python3 -m http.server "$PORT" --bind "$TARGET_IP" </dev/null >/dev/null 2>&1) &
NS_PID=$!
(cd / && exec python3 -m http.server "$PORT" --bind "$GATEWAY" </dev/null >/dev/null 2>&1) &
HOST_PID=$!

wait_listen() {   # $1 = optional "ip netns exec NS" prefix, $2 = address; wait up to 15 s
  i=0
  while [ "$i" -lt 30 ]; do
    if $1 ss -ltn 2>/dev/null | grep -q "$2:$PORT"; then return 0; fi
    sleep 0.5; i=$((i + 1))
  done
  echo "FAIL: test listener on $2:$PORT did not start"; exit 1
}
wait_listen "ip netns exec $NS" "$TARGET_IP"
wait_listen "" "$GATEWAY"

F0=$(counter DOCKER-USER "$SUBNET")
I0=$(counter INPUT "$BRIDGE")

try() {   # prints "open" or "blocked"
  if $COMPOSE exec -T cowrie "$PY" -c "import socket,sys; socket.create_connection(('$1',$PORT),4)" >/dev/null 2>&1; then
    echo open; else echo blocked; fi
}
R_FWD=$(try "$TARGET_IP")
R_HOST=$(try "$GATEWAY")
F1=$(counter DOCKER-USER "$SUBNET")
I1=$(counter INPUT "$BRIDGE")

echo "Cowrie -> test \"Internet\" $TARGET_IP:$PORT : $R_FWD  (DOCKER-USER DROP packets $F0 -> $F1)"
echo "Cowrie -> VM itself      $GATEWAY:$PORT : $R_HOST  (INPUT DROP packets $I0 -> $I1)"

if [ "$R_FWD" = blocked ] && [ "$R_HOST" = blocked ] && [ "$F1" -gt "$F0" ] && [ "$I1" -gt "$I0" ]; then
  echo "PASS: Cowrie cannot open new outbound connections, and the HoneyLens DROP rules did the blocking"
  exit 0
fi
echo "FAIL: egress is not locked down as expected"; exit 1
