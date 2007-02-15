"""
Dtella - DNS Lookup Module
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
import dtella_crypto
from dtella_util import (Ad, cmpify_version, word_wrap, parse_bytes,
                         dcall_discard)

from twisted.python.runtime import seconds
from twisted.internet import reactor

import binascii
import struct
import time
import random

from twisted.names import client, dns


class DNSHandler(object):

    def __init__(self, main, dns_servers):
        self.main = main

        self.override_vc = cmpify_version(dtella_local.version)
        self.resetReportedVersion()

        self.cfg_lastUpdate = None
        self.cfg_busy = False
        self.cfg_cb = None

        # Increases logarithmically until we get a first DNS reply
        self.fail_delay = 10.0

        self.cfgRefresh_dcall = None

        self.minshare = 1
        self.version = None

        dns_servers = dns_servers[:]
        random.shuffle(dns_servers)

        self.resolver = client.Resolver(
            servers=[(ip, dns.PORT) for ip in dns_servers],
            timeout=(1,2,3))


    def resetReportedVersion(self):
        self.reported_vc = cmpify_version(dtella_local.version)


    def getConfigFromDNS(self, cb):
        # Requery the TXT record if we haven't gotten an update in the
        # last hour.

        stale = ((self.cfg_lastUpdate is None) or
                 (seconds() - self.cfg_lastUpdate >= 60*5))

        if cb:
            self.cfg_cb = cb

            if stale or self.cfg_busy:
                self.main.showLoginStatus(
                    "Requesting config from %s..." % dtella_local.dnshost,
                    counter=0)

        # If an update is already in progress, just wait for it.
        if self.cfg_busy:
            return

        # If we've done an update recently, then skip the query
        if (not stale) and cb:
            cb()
            return

        def err_cb(text):
            if cb:
                self.main.showLoginStatus(
                    "DNS query failed!  Trying to proceed without it...")

            self.doneGettingConfig()

        # Do Query
        self.cfg_busy = True
        try:
            d = self.resolver.query(
                dns.Query(dtella_local.dnshost, type=dns.TXT))
        except Exception, e:
            err_cb(str(e))
            return

        d.addCallback(self.handleTXT)
        d.addErrback(err_cb)


    def handleTXT(self, reply):

        if not reply[0]:
            # Empty response; hop to the error callback
            raise ValueError("Empty DNS Reply")

        state = self.main.state

        # Defaults
        self.minshare = 1
        self.version = None
        state.dns_pkhashes = set()
        state.dns_ipcache = (0, [])
        
        for a in reply[0]:
            data = a.payload.data[0]

            try:
                name, value = data.split('=', 1)
            except ValueError:
                continue

            name = name.lower()

            if name == 'minshare':
                try:
                    self.minshare = parse_bytes(value)
                except ValueError:
                    pass
                else:
                    cap = dtella_local.minshare_cap
                    if (cap is not None) and (self.minshare > cap):
                        self.minshare = cap

            elif name == 'version':
                try:
                    min_v, new_v, url = value.split()
                except ValueError:
                    pass
                else:
                    self.version = (min_v, new_v, url)

            elif name == 'pkhash':
                h = binascii.a2b_base64(value)
                state.dns_pkhashes.add(h)
            
            elif name == 'ipcache':
                try:
                    data = binascii.a2b_base64(value)
                    data = self.main.pk_enc.decrypt(data)
                except (ValueError, binascii.Error):
                    continue

                if (len(data)-4) % 6 != 0:
                    continue

                when, = struct.unpack("!I", data[:4])
                ipps = [data[i:i+6] for i in range(4, len(data), 6)]

                state.dns_ipcache = (when, ipps)

        self.cfg_lastUpdate = seconds()
        self.doneGettingConfig()


    def doneGettingConfig(self):

        self.cfg_busy = False

        self.schedulePeriodicUpdates()

        if self.cfg_cb:
            self.cfg_cb()
            self.cfg_cb = None

        else:
            if self.belowMinimumVersion():
                return

            self.reportNewVersion()


    def schedulePeriodicUpdates(self):
        if self.cfg_lastUpdate is not None:
            # Automatically query DNS a couple times a day
            when = random.uniform(3600*12, 3600*24)
        else:
            # If we've never gotten an update, request sooner
            when = self.fail_delay * random.uniform(0.8, 1.2)
            self.fail_delay = min(3600*2, self.fail_delay *= 1.5)

        if self.cfgRefresh_dcall:
            self.cfgRefresh_dcall.reset(when)

        def cb():
            self.cfgRefresh_dcall = None
            self.getConfigFromDNS(None)
        
        self.cfgRefresh_dcall = reactor.callLater(when, cb)


    def dtellaShutdown(self):
        dcall_discard(self, 'cfgRefresh_dcall')


    def belowMinimumVersion(self):

        if not self.version:
            return False

        min_v, new_v, url = self.version
        min_vc = cmpify_version(min_v)

        if self.override_vc < min_vc:

            self.main.shutdown(reconnect='no')
            
            text = (
                " ",
                "Your version of Dtella (%s) is too old to be used on this "
                "network.  Please upgrade to the latest version (%s)."
                % (dtella_local.version, new_v),
                " ",
                "[If unusual circumstances prevent you from upgrading, "
                "type !VERSION_OVERRIDE to attempt to connect using this "
                "unsupported client.]",
                " ",
                "Download link: %s" % url
                )

            for par in text:
                for line in word_wrap(par):
                    self.main.showLoginStatus(line)
            return True

        return False


    def reportNewVersion(self):

        if not self.version:
            return

        min_v, new_v, url = self.version
        new_vc = cmpify_version(new_v)

        if self.reported_vc < new_vc:
            
            if self.main.dch:
                say = self.main.dch.bot.say
                say("You have Dtella version %s.  "
                    "A newer version (%s) is available."
                    % (dtella_local.version, new_v))
                say("Download link: %s" % url)
                
                self.reported_vc = new_vc


    def overrideVersion(self):
        # User requested skipping of the minimum version control

        if self.version:
            min_v, new_v, url = self.version
            min_vc = cmpify_version(min_v)

            if not (self.override_vc < min_vc):
                return False

            self.override_vc = min_vc

        return True


    def ipToHostname(self, ad, cb):
        # Try to determine the hostname of the provided address.
        # When done, call the cb function.  If it fails, the
        # argument is None.

        revip = '.'.join('%d' % o for o in reversed(ad.ip))
        host = "%s.in-addr.arpa" % revip

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

        try:
            d = self.resolver.query(dns.Query(host, type=dns.PTR))
        except Exception, e:
            err(str(e))
            return

        d.addCallback(success)
        d.addErrback(err)

