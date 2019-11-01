.. SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)

XDP NAT demo
============

Overview
~~~~~~~~

This directory contains demo client and server applications along with a flow
manager tool to allow for the NAT functionality to be showcased.

Flow Manager Application
~~~~~~~~~~~~~~~~~~~~~~~~

The nat_flow_manager userspace application generates statistics and
automatically removes expired flows from the eBPF map.

It polls the eBPF flow map at a set time period defined by --poll_time
(default 10 seconds).

There are 3 flow stages defined: active, inactive and expired.

A flow is deemed active until it has stopped transmitting traffic for a set time
period defined by the --inactive_time argument (default is 15 secs) at which
point it is marked as inactive/idle. When a flow remains in this idle state for
a further time period set by the --expire_time argument (default 60 secs),
the flow manager program will deem it to be closed and will remove the flow from
the BPF map.

Note: The idle and expire time periods defaults are set for the demo use cases,
but may need to be increased for real world applications.

NAT Example
~~~~~~~~~~~

This demo assumes the nat programs is compiled as explained in the parent
README. This demo utilises 3 servers ::

                           +--------------+
                           |              |
                  +-------+|   NAT BPF    +--------+
                  |        |   10.0.0.4   |        |
                  |        |              |        |
                  |        +--------------+        |
                  |                                |
                  |                                |
           +------+-------+                +-------+------+
           |              |                |              |
           |    CLIENT    |                |    SERVER    |
           |    10.0.0.1  |                |    10.0.0.2  |
           |              |                |              |
           +--------------+                +--------------+

The client will send UDP traffic to the UDP Server via the NAT application.
The server will reflect back the same data to the client via the NAT.
By default the port range 25001 -> 25050 will be used but these can be altered
within the client and server arguments
(check --help for more information)

Load the server.py application on the Server ::

  python3 server.py

Load the nat application on the NAT server ::

  ./nat -i { DEV } -H load nat_prog

Load the required flow rules. To make this easy we will use a simple bash loop
to iterate through all of the required ports ::

 for i in $(seq 25001 25050); do ./nat mapfill nat_prog key_daddr 10.0.0.4 key_dport $i val_saddr 10.0.0.4 val_daddr 10.0.0.2 val_dport $i val_dmac 00:15:4d:13:14:b6 aggressive_reap 0; done

Note: the IPs and Server MAC address will need altered to match your environment

Finally send traffic to the NAT using the client app ::

  python3 client.py -s 10.0.0.4

The NAT application can now be used to monitor the environment ::

  python3 nat_flow_manager.py -i { DEV }

Note: To show per flow stats, enable verbose mode (-v)

The NAT manager application will automatically cleanup
expired flows once they are deemed idle (see --help for more
information)

Aggressive Reap Flows
~~~~~~~~~~~~~~~~~~~~~

The NAT eBPF application can automatically cleanup Aggressive reap flows once
the return packet is received. Firstly enable aggressive reap on the NAT
rules for the same port range as before.

 for i in $(seq 25001 25050); do ./nat mapfill nat_prog key_daddr 10.0.0.4 key_dport $i val_saddr 10.0.0.4 val_daddr 10.0.0.2 val_dport $i val_dmac 00:15:4d:13:14:b6 aggressive_reap 1; done

Now send a single request per flow using the client tool ::

 python3 client.py -s 10.0.0.4 --requests_per_conn 1

The server application counters will show incoming data, however the flow
manager should show close a small number of flows as they have been
automatically reaped by the eBPF application.
