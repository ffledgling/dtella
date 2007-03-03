"""
Dtella - State File Management Module
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


import struct
import random
import time
import socket
import heapq
from twisted.internet import reactor
import os
import os.path
import twisted.python.log

from dtella_util import Ad, dcall_discard


class StateManager(object):

    def __init__(self, main, filename, loadsavers):

        path = os.path.expanduser("~/.dtella")
        if path[:1] == '~':
            # Can't get a user directory, just save to cwd.
            self.filename = filename
        else:
            try:
                if not os.path.exists(path):
                    os.mkdir(path)
            except OSError:
                twisted.python.log.err()

            self.filename = "%s/%s" % (path, filename)

        self.main = main
        self.peers = {}   # {ipp -> time}

        self.loadsavers = set(loadsavers)

        self.loadState()

        self.saveState_dcall = None
        self.saveState()


    def loadState(self):
        # Call this once to load the state file
        
        try:
            f = file(self.filename, "rb")

            d = {}

            header, nkeys = struct.unpack("!6sI", f.read(10))

            if header != "DTELLA":
                raise ValueError

            for i in range(nkeys):
                klen, = struct.unpack("!I", f.read(4))
                
                k = f.read(klen)
                if len(k) != klen:
                    raise ValueError

                vlen, = struct.unpack("!I", f.read(4))
                
                v = f.read(vlen)
                if len(v) != vlen:
                    raise ValueError

                if k in d:
                    raise ValueError

                d[k] = v

            if f.read(1):
                raise ValueError

        except:
            d = {}

        # Process all the state data
        for ls in self.loadsavers:
            ls.load(self, d)


    def saveState(self):
        # Save the state file every few minutes
        
        def cb():
            when = random.uniform(5*60, 6*60)
            self.saveState_dcall = reactor.callLater(when, cb)

            d = {}

            # Store all state data to dictionary
            for ls in self.loadsavers:
                ls.save(self, d)

            # Write to file
            try:
                f = file(self.filename, "wb")

                keys = d.keys()
                keys.sort()

                f.write(struct.pack("!6sI", "DTELLA", len(keys)))

                for k in keys:
                    v = d[k]
                    f.write(struct.pack("!I", len(k)))
                    f.write(k)
                    f.write(struct.pack("!I", len(v)))
                    f.write(v)

                f.close()
                
            except:
                twisted.python.log.err()

        dcall_discard(self, 'saveState_dcall')

        cb()


    def getYoungestPeers(self, n):
        # Return a list of (time, ipp) pairs for the N youngest peers
        peers = zip(self.peers.values(), self.peers.keys())
        return heapq.nlargest(n, peers)


    def refreshPeer(self, ad, age):
        # Call this to update the age of a cached peer

        if not ad.auth_s():
            return

        ipp = ad.getRawIPPort()

        if age < 0:
            age = 0

        seen = time.time() - age

        try:
            old_seen = self.peers[ipp]
        except KeyError:
            self.peers[ipp] = seen
        else:
            if seen > old_seen:
                self.peers[ipp] = seen

        if self.main.icm:
            self.main.icm.newPeer(ipp, seen)

        # Truncate the peer cache if it grows too large
        target = 100

        if self.main.osm:
            target = max(target, len(self.main.osm.nodes))

        if len(self.peers) > target * 1.5:
            keep = set([ipp for when,ipp in self.getYoungestPeers(target)])

            for ipp in self.peers.keys():
                if ipp not in keep:
                    del self.peers[ipp]


##############################################################################


class StateError(Exception):
    pass


class LoadSaver(object):

    def getKey(self, d):
        try:
            return d[self.key]
        except KeyError:
            raise StateError("Not Found")


    def setKey(self, d, value):
        d[self.key] = value


    def unpackValue(self, d, format):
        try:
            v, = struct.unpack('!'+format, self.getKey(d))
            return v
        except (struct.error, ValueError):
            raise StateError("Can't get value")


    def packValue(self, d, format, data):
        self.setKey(d, struct.pack('!'+format, data))


    def unpackStrs(self, d):
        strs = []
        i = 0

        data = self.getKey(d)

        while i < len(data):
            slen, = struct.unpack("!I", data[i:i+4])
            i += 4
            s = data[i:i+slen]
            i += slen
            if len(s) != slen:
                return []
            strs.append(s)

        return strs


    def packStrs(self, d, strs):
        data = []
        for s in strs:
            data.append(struct.pack("!I", len(s)))
            data.append(s)

        self.setKey(d, ''.join(data))



class Persistent(LoadSaver):

    key = 'persistent'

    def load(self, state, d):
        try:
            state.persistent = bool(self.unpackValue(d, 'B'))
        except StateError:
            state.persistent = False


    def save(self, state, d):
        self.packValue(d, 'B', bool(state.persistent))



class LocalSearch(LoadSaver):

    key = 'localsearch'

    def load(self, state, d):
        try:
            state.localsearch = bool(self.unpackValue(d, 'B'))
        except StateError:
            state.localsearch = True


    def save(self, state, d):
        self.packValue(d, 'B', bool(state.localsearch))



class UDPPort(LoadSaver):

    key = 'udp_port'

    def load(self, state, d):
        
        try:
            state.udp_port = self.unpackValue(d, 'H')
            
        except StateError:
            # Pick a random UDP port to use.  Try a few times.
            for i in range(8):
                state.udp_port = random.randint(1024, 65535)
                
                try:
                    # See if the randomly-selected port is available
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.bind(('', state.udp_port))
                    s.close()
                    break
                except socket.error:
                    pass


    def save(self, state, d):
        self.packValue(d, 'H', state.udp_port)



class IPCache(LoadSaver):

    key = 'ipcache'

    def load(self, state, d):
        # Get IP cache
        try:
            ipcache = self.getKey(d)
            if len(ipcache) % 10 != 0:
                raise StateError
        except StateError:
            ipcache = ''

        now = time.time()

        for i in range(0, len(ipcache), 10):
            ipp, when = struct.unpack('!6sI', ipcache[i:i+10])
            state.refreshPeer(Ad().setRawIPPort(ipp), now-when)


    def save(self, state, d):
        ipcache = [struct.pack('!6sI', ipp, int(when))
                   for when, ipp in state.getYoungestPeers(128)]

        self.setKey(d, ''.join(ipcache))



class Suffix(LoadSaver):

    key = 'suffix'

    def load(self, state, d):
        try:
            state.suffix = self.getKey(d)[:8]
        except StateError:
            state.suffix = ""


    def save(self, state, d):
        self.setKey(d, state.suffix)



class DNSIPCache(LoadSaver):

    key = 'dns_ipcache'

    def load(self, state, d):

        # Get saved DNS ipcache
        try:
            dns_ipcache = self.getKey(d)
            if len(dns_ipcache) % 6 != 4:
                raise StateError
        except StateError:
            state.dns_ipcache = (0, [])
        else:
            when, = struct.unpack('!I', dns_ipcache[:4])
            ipps = [dns_ipcache[i:i+6]
                    for i in range(4, len(dns_ipcache), 6)]
            state.dns_ipcache = (when, ipps)


    def save(self, state, d):
        when, ipps = state.dns_ipcache
        d['dns_ipcache'] = struct.pack('!I', when) + ''.join(ipps)



class DNSPkHashes(LoadSaver):

    key = 'dns_pkhashes'

    def load(self, state, d):

        # Get saved DNS pkhashes
        try:
            state.dns_pkhashes = set(self.unpackStrs(d))
        except StateError:
            state.dns_pkhashes = set()


    def save(self, state, d):
        self.packStrs(d, state.dns_pkhashes)


client_loadsavers = [Persistent(),
                     LocalSearch(),
                     UDPPort(),
                     IPCache(),
                     Suffix(),
                     DNSIPCache(),
                     DNSPkHashes()]

bridge_loadsavers = [IPCache()]
