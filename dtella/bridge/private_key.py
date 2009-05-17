"""
Dtella - One-shot Private Key Generator Module
Copyright (C) 2008  Dtella Labs (http://www.dtella.org/)
Copyright (C) 2008  Paul Marks (http://www.pmarks.net/)

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

from Crypto.PublicKey import RSA
from Crypto.Util.randpool import RandomPool
from Crypto.Util.number import long_to_bytes
import binascii

try:
    from hashlib import md5
except ImportError:
    from md5 import md5


def makePrivateKey():
    # Generate private key
    k = RSA.generate(1024, RandomPool().get_bytes)

    # Generate Public Key Hash
    print "pkhash=" + binascii.b2a_base64(md5(long_to_bytes(k.n)).digest())

    # Show private key
    print "For ./dtella/bridge_config.py:"
    print "private_key = %s" % ((k.n, k.e, k.d, k.p, k.q),)


if __name__ == '__main__':
    makePrivateKey()
