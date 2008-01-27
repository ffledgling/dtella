"""
Dtella - DNS TXT Record Puller Module
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

import random
from twisted.names import client, dns


class DnsTxtPuller(object):

    def __init__(self, servers, hostname):
        self.servers = list(servers)
        self.hostname = hostname

        random.shuffle(servers)

        self.resolver = client.Resolver(
            servers=[(ip, dns.PORT) for ip in servers],
            timeout=(1,2,3))


    def startText(self):
        return "Requesting config from %s..." % self.hostname


    def query(self):
        d = self.resolver.query(
            dns.Query(self.hostname, type=dns.TXT))

        def cb(result):
            # Convert DNS reply into a simple list of strings.
            return [a.payload.data[0] for a in result[0]]

        d.addCallback(cb)
        return d

