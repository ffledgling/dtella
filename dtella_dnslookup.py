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
        
        dns_servers = list(dtella_local.dns_servers)
        random.shuffle(dns_servers)

        self.resolver = client.Resolver(
            servers=[(ip, dns.PORT) for ip in dns_servers],
            timeout=(1,2,3))


    def updateIfStale(self):
        # Requery the TXT record if we haven't gotten an update in the
        # last hour.

        if seconds() - self.lastUpdate < DNS_STALE_TIME:
            return

        self.main.showLoginStatus(
            "Requesting config from %s..." % dtella_local.dnshost, counter=0)

        if 'dns' in self.main.blockers:
            return

        self.main.addBlocker('dns')

        d = self.resolver.query(
            dns.Query(dtella_local.dnshost, type=dns.TXT))

        def err(text):
            self.main.showLoginStatus(
                "DNS query failed!  "
                "Trying to continue, but this may cause further problems.")
            self.main.removeBlocker('dns')

        d.addCallback(self.handleTXT)
        d.addErrback(err)


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

        self.lastUpdate = seconds()

        self.main.removeBlocker('dns')


    def handleTXT_minshare(self, value):
        print "minshare is '%s'" % value


    def handleTXT_version(self, value):
        print "version is '%s'" % value


    def handleTXT_pkhash(self, value):
        h = binascii.a2b_base64(value)
        self.pkhashes.add(h)


    def handleTXT_ipcache(self, value):

        try:
            data = binascii.a2b_base64(value)
            data = self.main.pk_enc.decrypt(data)
        except (ValueError, binascii.Error), why:
            return

        if (len(data)-4) % 6 != 0:
            return

        tm, = struct.unpack("!I", data[:4])

        age = max(time.time() - tm, 0)

        ipps = [data[i:i+6] for i in range(4, len(data), 6)]
        random.shuffle(ipps)

        for ipp in ipps:
            ad = Ad().setRawIPPort(ipp)
            self.main.state.refreshPeer(ad, age)


    def ipToHostname(self, ad, cb):
        # Try to determine the hostname of the provided address.
        # When done, call the cb function.  If it fails, the
        # argument is None.
        
        revip = '.'.join('%d' % o for o in reversed(ad.ip))
        host = "%s.in-addr.arpa" % revip

        d = self.resolver.query(
            dns.Query(host, type=dns.PTR))

        def success(reply):
            try:
                hostname = reply[0][0].payload.name.name
                if not hostname:
                    raise ValueError
            except:
                hostname = None
            cb(hostname)

        def err(why):
            cb(None)

        d.addCallback(success)
        d.addErrback(err)

