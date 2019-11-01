#!/usr/bin/env python3
# SPDX-License-Identifier: (GPL-2.0 OR BSD-2-Clause)
# Copyright (c) 2020 Netronome Systems, Inc.

import argparse
import os
import socket
import sys
import time
import threading

def listen(port, results, n):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))

    while True:
        data, address = sock.recvfrom(port)
        if data:
            results[n] = results[n] + 1
            sent = sock.sendto(data, address) # reflect data back

def main():
    parser = argparse.ArgumentParser(description="Traffic gen client")
    parser.add_argument('-p', '--start_port', action='store',
                        required=False, type=str, default=25001,
                        help='server start port')
    parser.add_argument('-n', '--number_of_ports', action='store',
                        required=False, type=int, default=50,
                        help='server number of ports')
    args = parser.parse_args()
    results    = [0] * args.number_of_ports

    for p in range(0, args.number_of_ports):
        t = threading.Thread(target=listen, args=(args.start_port + p,
                                                  results, p))
        t.daemon = True
        t.start()

    while(True):
        os.system("clear")
        print("Listen Port\tReqs")

        for thread in range(len(results)):
            print("%6d\t    %7d" % (args.start_port + thread, results[thread]))

        time.sleep(1)

if __name__ == "__main__":
    main()
