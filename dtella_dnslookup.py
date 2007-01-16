import dtella_local
import dtella_crypto
from dtella_util import Ad

from twisted.python.runtime import seconds

import binascii
import struct
import time
import random

from twisted.names import client, dns

DNS_STALE_TIME = 60*60

class DNSHandler(object):

    def __init__(self, main):
        self.main = main

        self.lastUpdate = seconds() - DNS_STALE_TIME - 1

        self.minshare = 1
        self.version = ''
        self.pkhashes = set()
        
        dns_servers = ['4.2.2.1','4.2.2.2','208.67.220.220','208.67.222.222']
        random.shuffle(dns_servers)

        self.resolver = client.Resolver(
            servers=[(ip, dns.PORT) for ip in dns_servers],
            timeout=(1,2,3))


    def updateIfStale(self):
        # Requery the TXT record if we haven't gotten an update in the
        # last hour.

        print "Seconds since last DNS update: %d" % (seconds() - self.lastUpdate)
        
        if seconds() - self.lastUpdate < DNS_STALE_TIME:
            return

        self.main.showLoginStatus("Downloading network configuration...",
                                  counter=0)

        if 'dns' in self.main.blockers:
            return

        self.main.addBlocker('dns')

        d = self.resolver.query(
            dns.Query(dtella_local.dnshost, type=dns.TXT))

        d.addCallback(self.handleTXT)
        d.addErrback(self.handleTXT_Error)


    def handleTXT(self, reply):

        # Clear out old values
        self.pkhashes = set()
        
        for a in reply[0]:
            data = a.payload.data[0]

            try:
                name, value = data.split('=', 1)
            except ValueError:
                continue

            try:
                f = getattr(self, 'handleTXT_' + name.lower())
            except AttributeError:
                continue

            f(value)

        print "handled"

        self.lastUpdate = seconds()

        self.main.removeBlocker('dns')


    def handleTXT_Error(self, data):
        print "DNS ERROR"
        print data

        self.main.removeBlocker('dns')


    def handleTXT_minshare(self, value):
        print "minshare is '%s'" % value


    def handleTXT_version(self, value):
        print "version is '%s'" % value


    def handleTXT_pkhash(self, value):

        h = binascii.a2b_base64(value)
        print "pkhash is '%s'" % binascii.hexlify(h)

        self.pkhashes.add(h)


    def handleTXT_ipcache(self, value):

        print "ipcache =", value

        try:
            data = binascii.a2b_base64(value)
            data = self.main.pk_enc.decrypt(data)
        except (ValueError, binascii.Error), why:
            print "DNS ipcache decrypt failed:", why
            return

        if (len(data)-4) % 6 != 0:
            return

        tm, = struct.unpack("!I", data[:4])

        age = max(time.time() - tm, 0)

        ipps = [data[i:i+6] for i in range(4, len(data), 6)]
        random.shuffle(ipps)

        print "DNS ipcache age = %d" % age

        for ipp in ipps:
            ad = Ad().setRawIPPort(ipp)

            print "Adding from DNS: %s" % ad.getTextIPPort()
            
            self.main.state.refreshPeer(ad, age)



