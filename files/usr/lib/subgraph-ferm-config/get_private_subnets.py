#!/usr/bin/env python

"""
This script prints out the RFC1918 subnets that we are currently part of.
"""

from ipaddress import IPv4Network, IPv4Address
import subprocess
import sys

RFC1918 = [
    IPv4Network(u'192.168.0.0/16'),
    IPv4Network(u'172.16.0.0/12'),
    IPv4Network(u'10.0.0.0/8')
]

def get_private_subnets(addrs):
    """
    >>> addrs = [
    ... "10.1.2.3/8",
    ... "192.168.0.1/0",
    ... "172.16.0.1/8",
    ... "172.30.1.1/16",
    ... "172.31.1.0/32",
    ... "172.32.1.0/16",
    ... "169.254.0.0/16",
    ... ]
    >>> get_private_subnets(addrs)
    ['10.0.0.0/8', '172.30.0.0/16', '172.31.1.0/32']
    """
    res = set()
    for addr in addrs:
        addr, maskbits = addr.split('/')
        addr = IPv4Address(unicode(addr))
        maskbits = int(maskbits)
        mask = (2**maskbits-1) << 32-maskbits
        net_addr = IPv4Address( int(addr.packed.encode('hex'), 16) & mask )
        network = IPv4Network(unicode('%s/%s' % (net_addr, maskbits)))
        assert addr in network, "BUG: %s should be in %s but it is not!" % (addr, network)
        if maskbits and any(network.subnet_of(private) for private in RFC1918):
            res.add(str(network))
    return sorted(res)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        addrs = subprocess.check_output(
            "ip -o -f inet addr show |"
            " fgrep -v oz- | awk '/scope global/ {print $4}'",
            shell=True).strip().split('\n')
        print "\n".join( get_private_subnets(addrs) )
    else:
        import doctest
        doctest.testmod(verbose=1)

