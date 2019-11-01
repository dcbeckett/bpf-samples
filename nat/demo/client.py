#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
# Copyright (c) 2020 Netronome Systems, Inc.

import argparse
import socket
import sys
import time
from threading import Thread

def send_traffic(server, port, connections, requests):
    server_address = (server, port)
    message = 'Hello NAT app'
    req = 0

    for c in range(connections):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(5)
        try:
            for r in range(requests):
                sent = sock.sendto(message.encode(), server_address)
                data, server = sock.recvfrom(4096)
                req += 1
        except socket.timeout:
            print("Socket timeout port:%d" % port)
        finally:
            sock.close()

    print("port:%d conns:%d total reqs:%d" % (port, connections, req))

def main():
    parser = argparse.ArgumentParser(description="Traffic gen client")
    parser.add_argument('-s', '--ip', action='store',
                        required=True, type=str, help='server ip')
    parser.add_argument('-p', '--start_port', action='store',
                        required=False, type=int, default=25001,
                        help='server start port')
    parser.add_argument('-n', '--number_of_ports', action='store',
                        required=False, type=int, default=50,
                        help='server number of ports')
    parser.add_argument('-c', '--conns_per_port', action='store',
                        required=False, type=int, default=1000,
                        help='connections per port')
    parser.add_argument('-r', '--requests_per_conn', action='store',
                        required=False, type=int, default=25,
                        help='requests per connection')
    args = parser.parse_args()

    for p in range(args.start_port, args.start_port + args.number_of_ports):
        t = Thread(target=send_traffic, args=(args.ip, p, args.conns_per_port,
                                              args.requests_per_conn))
        t.start()

if __name__ == "__main__":
    main()
