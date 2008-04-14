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

import dtella.local_config as local
import struct
import socket
from socket import inet_aton, inet_ntoa

from dtella.common.util import CHECK


class Ad(object):

    ip = None
    port = None
    orig_ip = None  # If an address gets NAT-remapped, this is the original.

    def __eq__(self, other):
        return (self.ip == other.ip and self.port == other.port)

    def __ne__(self, other):
        return not self == other

    def auth(self, kinds, main):
        if self.ip is None:
            return False

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
            if not local.validateIP(self.getIntTupleIP()):
                return False

        return True

    def isRFC1918(self):
        # TODO FIX
        ip = self.getIntTupleIP()
        return ((ip[0] == 10) or
                (ip[0] == 172 and 16<=ip[1]<=31) or
                (ip[0] == 192 and ip[1] == 168)
                )

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
