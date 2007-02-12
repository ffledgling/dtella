"""
Dtella - Utility Functions
Copyright (C) 2007  Paul Marks
http://www.dtella.org/

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

import dtella_local

import struct
import random
import sys
import fpformat
import re
import array

from twisted.python.runtime import seconds


def randbytes(n):
    return ''.join([chr(random.randint(0,255)) for i in range(n)])


def cmpify_version(ver):
    # Given a version string, turn it into something comparable.

    ver_re = re.compile("([0-9]*)(.*)")

    ver_parts = []
    
    for part in ver.split('.'):
        m = ver_re.match(part)
        spart = m.group(2)
        try:
            ipart = int(m.group(1))
        except ValueError:
            ver_parts.append((spart,))
        else:
            ver_parts.append((ipart, spart))

    return tuple(ver_parts)


def validateNick(nick):
    if len(nick) < 2:
        return "too short"

    if len(nick) > 30:
        return "too long"

    if not nick[0].isalpha():
        return "must start with a letter"

    chars = ("-0123456789"
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ[]^_`"
             "abcdefghijklmnopqrstuvwxyz{}"
             "!\"#%&'()*+,./:;=?@\\~")

    for c in nick:
        if c not in chars:
            return "contains an invalid character: '%s'" % c

    return ''


# Lock2Key algorithm from the DC++ wiki
# by Benjamin Bruheim, optimized by Dody Suria Wijaya (25% faster)
def lock2key(lock):
    "Generates response to $Lock challenge from Direct Connect Servers"
    lock = array.array('B', lock)
    ll = len(lock)
    key = list('0'*ll)
    for n in xrange(1,ll):
        key[n] = lock[n]^lock[n-1]
    key[0] = lock[0] ^ lock[-1] ^ lock[-2] ^ 5
    for n in xrange(ll):
        key[n] = ((key[n] << 4) | (key[n] >> 4)) & 255
    result = ""
    for c in key:
        if c in (0, 5, 36, 96, 124, 126):
            result += "/%%DCN%.3i%%/" % c
        else:
            result += chr(c)
    return result


class RandSet(object):
    
    def __init__(self, init=()):
        self.map = {}
        self.set = set()
        for o in init:
            self.add(o)

    def __contains__(self, o):
        return (o in self.map)

    def __nonzero__(self):
        return bool(self.map)

    def add(self, o):
        # Add o to the set
        if o not in self.map:
            r = (random.random(), o)
            self.map[o] = r
            self.set.add(r)

    def discard(self, o):
        # Drop o from the set
        try:
            r = self.map.pop(o)
        except KeyError:
            return
        self.set.remove(r)

    def pop(self):
        # Get random element fron the set
        o = self.set.pop()[1]
        del self.map[o]
        return o

    def clear(self):
        self.map.clear()
        self.set.clear()

    def peek(self):
        o = self.pop()
        self.add(o)
        return o


def dcall_discard(obj, attr):
    # If a dcall exists, cancel it, and set it to None
    dcall = getattr(obj, attr)
    if dcall:
        dcall.cancel()
        setattr(obj, attr, None)


def dcall_timeleft(d):
    return max(0, d.getTime() - seconds())


def get_os():
    os_map = [('bsd','B'), ('cygwin','C'), ('linux','L'),
              ('darwin','M'), ('sun','S'), ('win','W')]

    p = sys.platform.lower()

    for key,value in os_map:
        if key in p:
            return value

    return '?'


def get_version_string():
    return "Dt:%s/%s" % (dtella_local.version, get_os())


def remove_dc_escapes(text):
    return text.replace('&#124;','|').replace('&#36;','$')


def split_info(info):
    # Split a MyINFO string
    # [0:'description<tag>', 1:' ', 2:'speed_', 3:'email', 4:'sharesize', 5:'']

    if info:
        info = info.split('$',6)
        if len(info) == 6:
            return info

    # Too many or too few parts
    raise ValueError


def parse_dtella_tag(info):

    # Break up info string
    try:
        info = split_info(info)

    except ValueError:
        # This could be an 'offline info'.
        if (info[:4], info[-1:]) == ('<Dt:','>'):
            return info[1:-1]

    else:
        # Properly formatted; extract tag
        desc, tag = split_tag(info[0])
        if tag:
            try:
                pos = tag.rindex("Dt:")
                return tag[pos:]
            except ValueError:
                pass

    # Couldn't find dtella tag
    return ""


def parse_incoming_info(info):
    # Pull the location and share size out of an info string
    # Returns dcinfo, version, location, shared

    info = info.replace('\r','').replace('\n','')

    # Break up info string
    try:
        info = split_info(info)
    except ValueError:
        return ("", "", 0)

    # Check if the location has a user-specified suffix
    try:
        location, suffix = info[2][:-1].split('|', 1)
        suffix = suffix[:8]
    except ValueError:
        # No separator, use entire connection field as location name
        location = info[2][:-1]
    else:
        # Keep location, and splice out the separator
        info[2] = location + suffix + info[2][-1:]

    # Get share size
    try:
        shared = int(info[4])
    except ValueError:
        shared = 0

    return ('$'.join(info), location, shared)


def split_tag(desc):
    # Break 'description<tag>' into ('description','tag')
    tag = ''
    if desc[-1:] == '>':
        try:
            pos = desc.rindex('<')
            tag = desc[pos+1:-1]
            desc = desc[:pos]
        except ValueError:
            pass
    return desc, tag


def format_bytes(n):
    # Convert an integer into a Bytes representation
    n = float(n)
    suffix = ('B','KiB','MiB','GiB','TiB','PiB')
    i = 0
    while n >= 1024 and i < 5:
        n /= 1024
        i+=1

    if i:
        return "%s %s" % (fpformat.fix(n, 2), suffix[i])
    else:
        return "%d %s" % (n, suffix[i])


def parse_bytes(s):
    # Might raise ValueError
    
    mult = 1
    if s:
        i = 'KMGT'.find(s[-1].upper())
        if i > -1:
            s = s[:-1]
            mult = 1024 ** (i+1)

    return int(float(s) * mult)


def word_wrap(line, max_len=80):

    lines = []

    words = line.split(' ')
    i = 0

    while i < len(words):
        cur_line = None

        while i < len(words):
            word = words[i]

            if cur_line is None:
                cur_line = ''
            else:
                word = ' ' + word
                if len(cur_line) + len(word) > max_len:
                    break
            

            cur_line += word
            i += 1

        lines.append(cur_line)

    return lines


###########################################################################


class Ad(object):

    ip = None
    port = None
    orig_ip = None  # If an address gets NAT-remapped, this is the original.

    def __eq__(self, other):
        return (self.ip == other.ip and self.port == other.port)


    def __ne__(self, other):
        return not self == other


    def auth_s(self):
        # Authorize IP based on static filter

        if not self.ip:
            return False

        return dtella_local.validateIP(self.ip)


    def auth_b(self, main):
        # Authorize IP based on bans list

        if not self.ip:
            return False

        if main.osm:
            return not main.osm.banm.isBanned(self.getRawIPPort())
        else:
            return True


    def auth_sb(self, main):
        # Authorize IP based on static+bans

        return (self.auth_s() and self.auth_b(main))


    def isRFC1918(self):
        ip = self.ip
        return ((ip[0] == 10) or
                (ip[0] == 172 and 16<=ip[1]<=31) or
                (ip[0] == 192 and ip[1] == 168)
                )


    # Set Stuff
    def setTextIP(self, ip):
        parts = ip.split('.', 4)
        if len(parts) != 4:
            raise ValueError

        for i in range(4):
            parts[i] = int(parts[i])
            if not 0 <= parts[i] < 256:
                raise ValueError

        self.ip = tuple(parts)
        return self


    def setAddrTuple(self, addr):
        ip, port = addr
        self.setTextIP(ip)
       
        if not 0 < port < 65536:
            raise ValueError
        self.port = port
        
        return self


    def setTextIPPort(self, ip):
        ip, port = ip.split(':',2)

        port = int(port)

        if not 0 < port < 65536:
            raise ValueError

        self.setTextIP(ip)
        self.port = port
        return self


    def setRawIP(self, ip):
        try:
            ip = struct.unpack('!BBBB', ip)
        except struct.error:
            raise ValueError

        self.ip = ip
        return self


    def setRawIPPort(self, ipp):
        try:
            out = struct.unpack('!BBBBH', ipp)
        except struct.error:
            raise ValueError
        self.ip = out[:4]
        self.port = out[4]
        return self
        

    # Get Stuff
    def getTextIP(self):
        try:
            return "%d.%d.%d.%d" % self.ip
        except TypeError:
            return None


    def getAddrTuple(self):
        return (self.getTextIP(), self.port)


    def getTextIPPort(self):
        try:
            return "%d.%d.%d.%d:%d" % (self.ip + (self.port,))
        except TypeError:
            return None


    def getRawIP(self):
        try:
            return struct.pack('!BBBB', *self.ip)
        except (struct.error, TypeError):
            return None


    def getRawIPPort(self):
        try:
            addr = self.ip + (self.port,)
            return struct.pack('!BBBBH', *addr)
        except (struct.error, TypeError, IndexError):
            return None


