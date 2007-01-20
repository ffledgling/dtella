import dtella_local

import struct
import random
import os

from twisted.python.runtime import seconds


def randbytes(n):
    return ''.join([chr(random.randint(0,255)) for i in range(n)])


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
             "!\"#%&'()*+,./:;<=?@\\~")

    for c in nick:
        if c not in chars:
            return "contains an invalid character: '%s'" % c

    return ''


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
    return d.getTime() - seconds()


def get_os():
    os_map = {'nt':'W', 'posix':'L', 'mac':'M'}
    try:
        return os_map[os.name]
    except KeyError:
        return '?'


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


    def validate(self):
        if not self.ip:
            return False
        return dtella_local.validateIP(self.ip)


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
