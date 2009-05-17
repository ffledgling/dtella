"""
Dtella - Packet Encryption Module
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

from Crypto.Cipher import AES
from dtella.common.util import md5

class PacketEncoder(object):

    def __init__(self, key):
        self.aes = AES.new(md5(key).digest())


    def encrypt(self, data):
        # AES requires packets in blocks of 16 bytes so pad the packet with
        # its MD5 hash.  We need a minimum of 5 hash bytes.
        # There's also 1 byte at the end to store the hash length
        
        hlen = ((10-len(data)) % 16) + 5

        h = md5(data).digest()[:hlen] + '\0'*(hlen-16)

        data += h + chr(hlen)

        return self.aes.encrypt(data)


    def decrypt(self, data):
        if not (data and len(data) % 16 == 0):
            raise ValueError("Bad Length")

        data = self.aes.decrypt(data)

        hlen = ord(data[-1])

        if not (5 <= hlen < len(data)):
            raise ValueError("Bad Hash Length")

        h = data[-(hlen+1):-1][:16]
        data = data[:-(hlen+1)]

        if h != md5(data).digest()[:hlen]:
            raise ValueError("Bad Hash Value")

        return data

