#!/usr/bin/env python3
"""
DNS server mock for ipv6
"""
# original source code https://code.activestate.com/recipes/491264-mini-fake-dns-server/

import struct
import socket
import traceback
import argparse
import ipaddress


def dns_answer(data, ip):
    """
    DNS answer
    """
    if len(data) < 12:
        return None, None

    # read domain
    domain = b''
    query_type = (data[2] >> 3) & 15  # opcode
    if query_type == 0:  # standard query
        start = 12
        length = data[start]
        while length > 0:
            domain += data[start + 1:start + length + 1] + b'.'
            start += length + 1
            length = data[start]
    else:
        return None, None
    domain = domain.decode('utf8')

    if not domain:
        return None, None

    # compile aswer
    raw_ip = ip.packed
    packet = b''.join([
        data[:2],  # identification
        b'\x81\x80',  # flags
        data[4:6],  # number of questions
        data[4:6],  # number of aswers
        b'\x00\x00',  # number of authority
        b'\x00\x00',  # number of additional
        data[12:],  # original question
        b'\xc0\x0c',  # pointer domain name
        b'\x00\x01' if ip.version == 4 else b'\x00\x1c', # type
        b'\x00\x01\x00\x00\x00\x00', # class, ttl
        struct.pack('!H', len(raw_ip)),  # resource data length
        raw_ip,
    ])

    return domain, packet


def run_server(host, port, ip, verbose):
    """
    Run mock dns server
    """
    print(f'running dns sever on {host} port {port}')
    print(f'everything is resolved to {ip}')

    parsed_ip = ipaddress.ip_address(ip)
    server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    server.bind((host, port))

    while True:
        try:
            data, addr = server.recvfrom(512)
            domain, answer = dns_answer(data, parsed_ip)
            if domain is not None:
                server.sendto(answer, addr)
                if verbose:
                    print(f'{domain} {ip}')
        except Exception:
            traceback.print_exc()
        except KeyboardInterrupt:
            print('user requested exit')
            server.close()
            break


def main():
    """
    Serve DNS
    """
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=__doc__,
    )
    parser.add_argument('--ip', required=True, help='ip address assigned to each query')
    parser.add_argument('--host', default='::1', help='host to bid')
    parser.add_argument('--port', required=True, type=int, help='port to bind')
    args = parser.parse_args()
    run_server(args.host, args.port, args.ip, verbose=True)


# entrypoint
if __name__ == '__main__':
    main()
