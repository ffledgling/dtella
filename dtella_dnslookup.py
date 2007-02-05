import dtella_local
import dtella_crypto
import dtella_core
from dtella_util import Ad, cmpify_version, word_wrap

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
        self.version = None
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
            if self.versionBelowMinimum():
                self.main.addBlocker('old_version')
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
                "DNS query failed!  Trying to proceed without it...")

            # Pull out cached copy of the public key(s)
            if not self.pkhashes and self.main.state.pkhashes:
                self.pkhashes = set(self.main.state.pkhashes)
            
            self.main.removeBlocker('dns')

        d.addCallback(self.handleTXT)
        d.addErrback(err)


    def handleTXT(self, reply):

        # Clear out old values
        self.minshare = 1
        self.version = None
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

        # Update local cache of public keys
        self.main.state.pkhashes = list(self.pkhashes)

        # Check for minimum version
        if self.versionBelowMinimum():
            self.main.addBlocker('old_version')
        else:
            if 'old_version' in self.main.blockers:
                self.main.removeBlocker('old_version')

            # We know they have the minimum version, but
            # now check if they have the *latest* version.
            self.sendVersionMessage()

        self.main.removeBlocker('dns')


    def handleTXT_minshare(self, value):
        print "minshare is '%s'" % value


    def handleTXT_version(self, value):
        try:
            min_v, new_v, url = value.split()
        except ValueError:
            return
        else:
            self.version = (min_v, new_v, url)


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


    def sendVersionMessage(self):

        if not self.version:
            return False

        min_v, new_v, url = self.version
        my_v = dtella_core.VERSION
        my_vc = cmpify_version(my_v)
        new_vc = cmpify_version(new_v)

        if my_vc < new_vc:
            if self.main.dch:
                self.main.dch.bot.say(
                    "Your version of Dtella (%s) is outdated.  Get "
                    "version %s here:" % (my_v, new_v))
                self.main.dch.bot.say(url)


    def versionBelowMinimum(self):

        if not self.version:
            return False

        min_v, new_v, url = self.version
        my_v = dtella_core.VERSION
        my_vc = cmpify_version(my_v)
        min_vc = cmpify_version(min_v)

        if my_vc < min_vc:
            text = (
                "Your version of Dtella (%s) is too old to be used on this "
                "network.  Please upgrade to the latest version (%s).  "
                "(If you *REALLY* want to try using your old version, type "
                "!VERSION_OVERRIDE.)"
                % (my_v, new_v)
                )

            for line in word_wrap(text):
                self.main.showLoginStatus(line)

            self.main.showLoginStatus(" ")
            self.main.showLoginStatus("Download link: %s" % url)
            return True

        else:
            return False


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

