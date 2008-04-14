"""
Dtella - IPv4 Address Manipulation Functions
Copyright (C) 2008  Dtella Labs (http://www.dtella.org)
Copyright (C) 2008  Paul Marks

$Id$

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""

# Note that there's no IPv6 stuff here.  If Dtella and IPv6 are ever popular
# at the same time, we'll have to redesign the protocol to handle it.

import dtella.local_config as local
import bisect
import struct
import socket
from socket import inet_aton, inet_ntoa

from dtella.common.util import CHECK


# Class for holding an IP:Port, and converting to/from various formats.
class Ad(object):

    ip = None       # ip is a 4-byte string
    port = None     # port is a plain old integer
    orig_ip = None  # If an address gets NAT-remapped, this is the original.

    def __eq__(self, other):
        return (self.ip == other.ip and self.port == other.port)

    def __ne__(self, other):
        return not self == other

    def auth(self, kinds, main):
        if self.ip is None:
            return False

        int_ip = self.getIntIP()

        if 'b' in kinds:
            # Bans
            if main.osm and main.osm.banm.isBanned(self.getRawIPPort()):
                return False

        if 'x' in kinds:
            # Bridge/Cache Exempt IPs
            if self.ip in main.state.exempt_ips:
                return True

        if 's' in kinds:
            # Static evaluation
            if not local_matcher.containsIP(int_ip):
                return False

        return True

    def isRFC1918(self):
        return rfc1918_matcher.containsIP(self.getIntIP())

    # Set Stuff
    def setTextIP(self, ip):
        if ip.count('.') != 3:
            raise ValueError("Wrong number of octets")

        try:
            self.ip = inet_aton(ip)
        except socket.error:
            raise ValueError("Can't parse IP")

        return self

    def setAddrTuple(self, addr):
        ip, port = addr
        self.setTextIP(ip)
       
        if not 0 <= port < 65536:
            raise ValueError("Port out of range")
        self.port = port
        
        return self

    def setTextIPPort(self, ip):
        ip, port = ip.split(':', 2)

        port = int(port)

        if not 0 <= port < 65536:
            raise ValueError("Port out of range")

        self.setTextIP(ip)
        self.port = port
        return self

    def setRawIP(self, ip):
        try:
            self.ip, = struct.unpack('!4s', ip)
        except struct.error:
            raise ValueError("Not a valid 4-byte string")
        return self

    def setRawIPPort(self, ipp):
        try:
            self.ip, self.port = struct.unpack('!4sH', ipp)
        except struct.error:
            raise ValueError("Not a valid 6-byte string")
        return self

    def setIntIP(self, ip):
        try:
            self.ip = struct.pack('!i', ip)
        except struct.error:
            raise ValueError("Not a valid IP integer")
        return self


    # Get Stuff
    def getTextIP(self):
        CHECK(self.ip is not None)
        return inet_ntoa(self.ip)

    def getAddrTuple(self):
        CHECK(self.ip is not None and self.port is not None)
        return (inet_ntoa(self.ip), self.port)

    def getTextIPPort(self):
        CHECK(self.ip is not None and self.port is not None)
        return "%s:%d" % (inet_ntoa(self.ip), self.port)

    def getRawIP(self):
        CHECK(self.ip is not None)
        return self.ip

    def getRawIPPort(self):
        CHECK(self.ip is not None and self.port is not None)
        return self.ip + struct.pack('!H', self.port)

    def getIntIP(self):
        CHECK(self.ip is not None)
        return struct.unpack('!i', self.ip)[0]

    def getIntTupleIP(self):
        CHECK(self.ip is not None)
        return tuple(ord(o) for o in self.ip)


# For backward compatibility
import dtella.common.util
dtella.common.util.Ad = Ad


# Convert 24 -> 0xFFFFFF00
def CidrNumToMask(num):
    if num == 0:
        return 0
    elif 1 <= num <= 32:
        return ~0 << (32 - num)
    else:
        raise ValueError("CIDR number out of range")


# Convert 0xFFFFFF00 -> 24
def MaskToCidrNum(mask):
    subnet = 0
    b = ~0 << 31
    while ((b & mask) == b) and (subnet < 32):
        b >>= 1
        subnet += 1

    if subnet == 0 and mask != 0:
        raise ValueError("Not a valid subnet mask")

    return subnet


# Convert (ip, mask) to a "1.2.3.4/5" string
# Might raise ValueError.
def IPMaskToCidrString(ipmask):
    ip, mask = ipmask
    return "%s/%d" % (Ad().setIntIP(ip).getTextIP(), MaskToCidrNum(mask))


# Convert "1.2.3.4/5" into (ip, mask) ints
# Might raise ValueError.
def CidrStringToIPMask(cidr):
    try:
        ip, subnet = cidr.split('/', 1)
    except ValueError:
        ip, subnet = cidr, "32"

    ip = Ad().setTextIP(ip).getIntIP()
    mask = CidrNumToMask(int(subnet))
    return ip, mask


# Test if an IP is a member of a subnet, or if a subnet is a subset of another
# subnet.  Both arguments are (ip, mask) tuples.  A plain IP address should
# have a mask of ~0, which corresponds to a /32.
def IsSubsetOf(candidate, group):
    c_ip, c_mask = candidate
    g_ip, g_mask = group

    # If the candidate is less specific than the group (i.e. the candidate
    # mask has fewer bits), then it can't be a subset.
    if (c_mask & g_mask) != g_mask:
        return False

    # Candidate is a subset if their prefixes are equal.
    return (c_ip & g_mask) == (g_ip & g_mask)


# Class for keeping track of a list of subnets, and testing whether
# an IP address is a member of any of the subnets.  Subnets can be added
# individually, but deleting requires a complete rebuild.
#
# IP lookups are O(log n) because of binary search.  In order for binary
# search to work correctly, the class maintains some invariants:
#
# - The list of (ip, mask) tuples is kept in sorted order.
# - On insertion, any stray bits after the mask are stripped from the ip.
# - When a subnet is added that is a superset of existing subnets, those
#   existing subnets are deleted.
#
# All this basically means that we keep a sorted list of prefixes, and
# we can quickly search for the one prefix that might match a given IP.
# Once the prefix is found, we use the IsSubsetOf() function to see if
# the IP does in fact have that prefix.
#
class SubnetMatcher(object):

    def __init__(self, initial_ranges=None):
        self.nets = []
        if initial_ranges:
            for r in initial_ranges:
                self.addRange(CidrStringToIPMask(r))

    def addRange(self, ipmask):
        ip, mask = ipmask
        ipmask = (ip & mask, mask)

        # See if this range is already covered.
        if self.containsRange(ipmask):
            return

        # Delete any existing ranges that are covered by this new range.
        deletes = []
        for i, old_ipmask in enumerate(self.nets):
            if IsSubsetOf(old_ipmask, ipmask):
                deletes.append(i)
        for i in reversed(deletes):
            del self.nets[i]

        # Insert the new range
        bisect.insort_right(self.nets, ipmask)

    def containsRange(self, ipmask):
        i = bisect.bisect_right(self.nets, ipmask)
        if i == 0:
            return False
        return IsSubsetOf(ipmask, self.nets[i-1])

    def containsIP(self, int_ip):
        return self.containsRange((int_ip, ~0))

    def clear(self):
        del self.nets[:]

# Create a subnet matcher for RFC1918 addresses.
rfc1918_matcher = SubnetMatcher(
    ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'])

# Create a subnet matcher for locally-configured IPs.
local_matcher = SubnetMatcher(local.allowed_subnets)

