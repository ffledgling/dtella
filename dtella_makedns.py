import dtella_local
import dtella_crypto
from dtella_util import Ad

import struct
import binascii
import time

import random

cache = [('128.211.194.101',41234),
         ('128.211.207.82',41234),
         ('128.211.220.126',13373),
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

