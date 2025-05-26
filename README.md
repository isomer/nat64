# eBPF XDP NAT64

A simplistic nat64 ebpf program for XDP.

This is an eBPF program that performs nat64 using the XDP hook.  Packets
received to the magic mac address 02:00:00:00:00:64 are translated from IPv4 to
IPv6 and visa versa and transmitted out the same interface.
