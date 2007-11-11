#!/usr/bin/env python

"""
Dtella - One-shot DNS Generator Module
Copyright (C) 2007  Dtella Labs (http://www.dtella.org/)
Copyright (C) 2007  Paul Marks (http://www.pmarks.net/)

$Id: dtella.py 460 2007-11-11 04:12:11Z paul248 $

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
import dtella_crypto
from dtella_util import Ad

import struct
import binascii
import time

import random

# Manually build an IP cache
cache = [('1.2.3.4',41234),
         ]

data = []

#data.append(struct.pack("!I", int(time.time())))
data.append("\xFF\xFF\xFF\xFF")

for addr in cache:
    ad = Ad().setAddrTuple(addr)
    data.append(ad.getRawIPPort())


pk_enc = dtella_crypto.PacketEncoder(dtella_local.network_key)

data = pk_enc.encrypt(''.join(data))

print "ipcache=" + binascii.b2a_base64(data)


# Generate public/private keys
from Crypto.PublicKey import RSA
from Crypto.Util.randpool import RandomPool
from Crypto.Util.number import long_to_bytes
import md5, binascii

k = RSA.generate(1024, RandomPool().get_bytes)

print "pkhash=" + binascii.b2a_base64(md5.new(long_to_bytes(k.n)).digest())

print "For dtella_bridge_config.py:"
print "private_key = %s" % ((k.n, k.e, k.d, k.p, k.q),)

