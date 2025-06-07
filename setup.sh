#!/bin/sh
set -xe

DEV=test0
NATIP4=100.64.0.64
NATIP6=fe80::64
V6PREFIX=64:ff9b
MAGICMAC=02:00:00:00:00:64

ip link del $DEV || true

ip link add $DEV type veth

# Disable checksum offload.  Possibly only needed for debugging checksums
ethtool -K veth0 tx-checksumming off rx-checksumming off

#ip link set dev $DEV xdpgeneric obj nat64.o sec xdp verbose
LIBXDP_SKIP_DISPATCHER=1 ./nat64cli $DEV

ip link set up dev $DEV
#ip addr add 10.0.1.1/24 dev $DEV

ip link set up dev veth0
ip addr add 100.64.0.1/10 metric 10 dev veth0

ip neigh add fe80::64 lladdr $MAGICMAC dev veth0 ||
    ip neigh replace fe80::64 lladdr $MAGICMAC dev veth0
ip neigh add 100.64.0.64 lladdr $MAGICMAC dev veth0 ||
    ip neigh replace 100.64.0.64 lladdr $MAGICMAC dev veth0

ip route add $V6PREFIX::/96 via fe80::64 dev veth0

ip route add 192.168.4.4 via 100.64.0.64 dev veth0
ip neigh add proxy 192.168.4.4 dev wireless
ip addr add $V6PREFIX::192.168.4.4 dev veth0

echo 1 | tee \
    /proc/sys/net/ipv4/conf/wireless/proxy_arp \
    /proc/sys/net/ipv4/conf/veth0/forwarding \
    /proc/sys/net/ipv4/conf/wireless/forwarding

# Tail the trace log, when you press ^C, dump the counters
cat /sys/kernel/tracing/trace_pipe || bpftool map dump name nat64_counters
