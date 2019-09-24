.. SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP NAT
========

Overview
~~~~~~~~

Network Address Translation (NAT) maps one network space to another.

This program implements Source NAT (SNAT) and Destination NAT (DNAT) for
IPv4 UDP traffic. SNAT alters the sender IP and port number whilst DNAT alters
the destination IP and port number.

For SNAT, the sender's IP address is fixed, whilst the source port
varies for each individual flow. For DNAT, the destination IP
address and port is fixed.

The host controller pre-defines these values through rules stored
within a eBPF map. Each rule is specified based on a listening port and
there can be multiple rules per instance ::

 Rule:     KEY: LISTENING_IP:PORT   VALUE: SNAT_IP, DNAT_IP:PORT

For new incoming connections, the program will obtain a unique SNAT port with a
random number generator. If this tuple is already in use, another random port is
attempted.

NAT Example
~~~~~~~~~~~

Example rule: incoming traffic entering public address 200.1.1.1 port 443 NAT to
SNAT IP 1.1.1.1 and DNAT IP 2.2.2.2 port 5100 ::

 Rule:     ANY:ANY -> 200.1.1.1:443 [NAT'd] 1.1.1.1:? -> 2.2.2.2:5100

Client 100.1.1.1:25457 connects to the NAT Gateway ::

 New Flow: 100.1.1.1:25457 -> 200.1.1.1:443

The eBPF program looks up the rule for 200.1.1.1:443. Random SNAT port 42369 is
picked. ::

 New Flow: 100.1.1.1:25457 -> 200.1.1.1:443 [NAT'd] 1.1.1.1:42369 -> 2.2.2.2:5100

The tuple is stored within the 'flow map' to allow for future packets to re-use
the same NAT values. A second entry for the reverse tuple is also added so that
return traffic can be routed back to the user ::

 Rev Flow: 2.2.2.2:5100 -> 1.1.1.1:42369 [NAT'd] 200.1.1.1:443 -> 100.1.1.1:25457

The packet headers are modified to the NAT values, IPv4 and UDP checksums
are updated and the NAT'd packet is sent out of the network interface.

Aggressive Reap Flows
~~~~~~~~~~~~~~~~~~~~~

The eBPF program has an auto clean up feature called 'Aggressive Reap'.
This feature is built for RPC or ping like traffic patterns, were there is
a single outgoing and return packet per flow.

For example, an application trying to find a server with the lowest latency may
during the setup stage, send a single UDP ping packet to all available servers
via a dedicated ping port.
Each NAT gateway may have thousands of clients doing this pre-setup stage, hence
the eBPF flow map could be filled within several minutes.

If this dedicated ping port is set with an aggressive reap flag, the tuple
entries will be automatically reaped once the return ping packet is received,
minimising the level of pruning required by the host.

Minimum Requirements
~~~~~~~~~~~~~~~~~~~~
 - Clang/LLVM
 - Linux kernel 4.20 (for HW offload)
 - Agilio® eBPF map update enabled firmware (for HW offload) *

* Available on request

Building the Program
~~~~~~~~~~~~~~~~~~~~

To compile both the XDP program and the user space utility ::

 # make

This should produce an ELF object file containing the XDP NAT code
(''nat_kern.o''), along with a user space utility (''nat'').

Prepare / Clean up
~~~~~~~~~~~~~~~~~~

Mount the bpffs virtual file system (needs to be done only once) ::

    # mount bpffs /sys/fs/bpf -t bpf

Remove maps previously pinned ::

    # rm /sys/fs/bpf/nat_prog*

Set ulimit max memory size to allow for large maps to be loaded ::

    # ulimit -l unlimited

Load program and maps
~~~~~~~~~~~~~~~~~~~~~

The user space tool can be used to:

1) Load the BPF programs and pin the maps to /sys/fs/bpf
2) Manage the Gateway listening port rules for new flows
3) Add and prune individual client flows

To load the eBPF program on HW offload and automatically pin the maps ::

    # ./nat -i { DEV } -H load nat_prog
     Pinned map at /sys/fs/bpf/nat_prog_rules
     Pinned map at /sys/fs/bpf/nat_prog_flows
     Pinned map at /sys/fs/bpf/nat_prog_stats

Note, modes available:
  -H    Hardware Mode (XDPOFFLOAD)
  -N    Native Mode (XDPDRV)
  -S    SKB Mode (XDPGENERIC)

The XDP program is loaded from file ''nat_kern.o''. Note that ''nat_prog'' is
the name used to pin the map but this can be altered as required, e.g. if
the program is run on multiple netdevs, each instance can be given a unique name

To exit polling and unload the program, hit ''Ctrl-C''.

Add listening port rules
~~~~~~~~~~~~~~~~~~~~~~~~

The tool is polling for perf events immediately after loading the program and
blocks the console, therefore map rules have to be added from another terminal.

To add a new rule ::

 # ./nat mapfill nat_prog key_daddr 200.1.1.1 key_dport 443 val_saddr 1.1.1.1 val_daddr 2.2.2.2 val_dport 5100 val_dmac 00:15:4d:13:14:b6 aggressive_reap 0

Path ''nat_prog'' depends on the instance name passed when loading the
program.
val_dmac is the mac address for the next hop e.g. the gateways router
agressive_reap is an optional arg and defaults to 0

Flow Monitoring
~~~~~~~~~~~~~~~

When a new flow is received by the application. The userspace app will
show the clients flow details on its console ::

 687.308591 New Conn  100.1.1.1:25457 > 200.1.1.1:443 NAT 1.1.1.1:42369 > 2.2.2.2:5100

Note: By default the console application is not notified about reap flows, this
can be enabled by setting the LOG_REAP_FLOWS parameter to 1 within nat_kern.c.

The eBPF application stores Byte and Packet counters for each flow,
An external application can poll these flow counters through bpftool ::

 bpftool -p map dump pinned /sys/fs/bpf/nat_prog_flows
 [{
        "key": ["0x64","0x01","0x01","0x01","0xc8","0x01","0x01","0x01","0x63","0x71","0x01","0xbb"
        ],
        "value": ["0x01","0x01","0x01","0x01","0x02","0x02","0x02","0x02","0xa5","0x81","0x13","0xec",
                  "0x00","0x15","0x4d","0x13","0x14","0xb6","0x00","0x00",
                  "0x30","0x00","0x00","0x00","0x00","0x00","0x00","0x00",
                  "0x80","0x1b","0x01","0x00","0x00","0x00","0x00","0x00"
        ]
    }
 ]

The counters are stored within the final 16 hex values.
The number of packets in the flow (0x 00 00 00 00 00 00 00 30 = 48)
followed by the total number of Bytes (0x 00 00 00 00 00 01 1b 80 = 72,576)

Note BPF maps are in host endian.

Note: see struct flow_key and struct egress_nat_value within nat_common.h
to obtain the full map value layout.

Flow Pruning
~~~~~~~~~~~~

When a flow is deemed inactive by a third party tool e.g. there has been no
flow traffic within the last 2 minutes, the flow can be removed from the map
with the prunenat command..
The prune commands removes the flow in both directions ::

 # ./nat prunenat nat_prog key_saddr 100.1.1.1 key_sport 25457 key_daddr 200.1.1.1 key_dport 443
  Deleted flow from map: 100.1.1.1:25457 -> 200.1.1.1:443
  Deleted flow from map: 2.2.2.2:5100 -> 1.1.1.1:42369

Removing listening port rules
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Flow rules can be deleted with the mapunfill command ::

    # ./nat mapunfill nat_prog key_daddr 200.1.1.1 key_dport 443
