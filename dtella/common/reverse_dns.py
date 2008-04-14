"""
Dtella - Reverse DNS Module
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

from twisted.names import client, dns
import random


class ReverseLookupHandler(object):

    def __init__(self):
        # Merge rdns_servers entries from local and bridge configs.
        servers = set()
        try:
            import dtella.local_config as local
            servers.update(local.rdns_servers)
        except (ImportError, AttributeError):
            pass
        try:
            import dtella.bridge_config as cfg
            servers.update(cfg.rdns_servers)
        except (ImportError, AttributeError):
            pass

        # Convert to list, and randomize.
        servers = list(servers)
        random.shuffle(servers)

        self.resolver = client.Resolver(
            servers=[(ip, dns.PORT) for ip in servers],
            timeout=(1,2,3))


    def ipToHostname(self, ad):
        # Try to determine the hostname of the provided address.
        # Returns a deferred, which will callback but never errback.
        # If successful, the callback argument is a hostname string,
        # None otherwise.

        revip = '.'.join(str(ord(o)) for o in ad.getRawIP()[::-1])
        host = "%s.in-addr.arpa" % revip

        def cb(result):
            try:
                hostname = result[0][0].payload.name.name
                if not hostname:
                    return None
            except:
                return None

            return hostname

        def eb(failure):
            return None

        d = self.resolver.query(dns.Query(host, type=dns.PTR))
        d.addCallbacks(cb, eb)
        return d


# Simplified lookup interface
ipToHostname = ReverseLookupHandler().ipToHostname
