#from Crypto.Util.randpool import RandomPool
#from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
import md5

#r = RandomPool()
#x = RSA.generate(512, r.get_bytes, progress)

class PacketEncoder(object):

    def __init__(self, key):
        self.aes = AES.new(md5.new(key).digest())


    def encrypt(self, data):
        # AES requires packets in blocks of 16 bytes so pad the packet with
        # its MD5 hash.  We need a minimum of 5 hash bytes.
        # There's also 1 byte at the end to store the hash length
        
        hlen = ((10-len(data)) % 16) + 5

        h = md5.new(data).digest()[:hlen] + '\0'*(hlen-16)

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

        if h != md5.new(data).digest()[:hlen]:
            raise ValueError("Bad Hash Value")

        return data
    
