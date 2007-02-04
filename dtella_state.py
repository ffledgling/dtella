import struct
import random
import time
import socket
import heapq
from twisted.internet import reactor
import os
import os.path

from dtella_util import Ad, dcall_discard

class StateManager(object):

    def __init__(self, main, filename):

        path = os.path.expanduser("~/.dtella")
        if not os.path.exists(path):
            os.mkdir(path)

        self.filename = "%s/%s" % (path, filename)

        self.main = main
        self.peers = {}   # {ipp -> time}

        self.loadState()

        self.saveState_dcall = None
        self.saveState()


    def loadState(self):
        # Call this once to load the state file
        
        try:
            d = self.readDict()
        except:
            d = {}

        # Get UDP port
        try:
            self.udp_port, = struct.unpack('!H', d['udp_port'])
            
        except (KeyError, struct.error):

            # Pick a random UDP port to use.  Try a few times.
            for i in range(8):
                self.udp_port = random.randint(1024, 65535)
                
                try:
                    # See if the randomly-selected port is available
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.bind(('', self.udp_port))
                    s.close()
                    break
                except socket.error:
                    pass

        # Get Persistent flag
        try:
            self.persistent = bool(*struct.unpack('!B', d['persistent']))
        except (KeyError, struct.error):
            self.persistent = False

        # Get IP cache
        try:
            ipcache = d['ipcache']
        except KeyError:
            ipcache = ''

        if len(ipcache) % 10 != 0:
            ipcache = ''

        now = time.time()

        for i in range(0, len(ipcache), 10):
            ipp, when = struct.unpack('!6sI', ipcache[i:i+10])
            self.refreshPeer(Ad().setRawIPPort(ipp), now-when)

        # Get Location suffix
        try:
            self.suffix = d['suffix'][:8]
        except KeyError:
            self.suffix = ""


    def saveState(self):
        # Save the state file every few minutes
        
        def cb():
            when = random.uniform(5*60, 6*60)
            self.saveState_dcall = reactor.callLater(when, cb)

            d = {}

            d['udp_port'] = struct.pack('!H', self.udp_port)

            d['persistent'] = struct.pack('!B', self.persistent)

            peerdata = [struct.pack('!6sI', ipp, int(when))
                        for when, ipp in self.getYoungestPeers(128)]
            
            d['ipcache'] = ''.join(peerdata)

            d['suffix'] = self.suffix
            
            self.writeDict(d)

        dcall_discard(self, 'saveState_dcall')

        cb()


    def writeDict(self, d):
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


    def readDict(self):
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

        return d


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
        icm = self.main.icm

        try:
            old_seen = self.peers[ipp]

        except KeyError:
            self.peers[ipp] = seen
            if icm:
                icm.newPeer(ipp, seen)

        else:
            if seen > old_seen:
                self.peers[ipp] = seen
                if icm:
                    icm.youngerPeer(ipp, seen)

        # Truncate the peer cache if it grows too large
        target = 100

        if self.main.osm:
            target = max(target, len(self.main.osm.nodes))

        if len(self.peers) > target * 1.5:
            keep = set([ipp for when,ipp in self.getYoungestPeers(target)])

            for ipp in self.peers.keys():
                if ipp not in keep:
                    del self.peers[ipp]



