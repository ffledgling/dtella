import fixtwistedtime

import struct
import hmac
import md5
import heapq
import time
import random
import bisect
import weakref
import re
import socket
from binascii import hexlify

from twisted.internet.protocol import Protocol, DatagramProtocol
from twisted.internet import reactor
from twisted.python.runtime import seconds
import twisted.internet.error

import dtella_local
import dtella_crypto
import dtella_dnslookup
import dtella_state
from dtella_util import (RandSet, Ad, dcall_discard, dcall_timeleft, randbytes,
                         validateNick, word_wrap)

try:
    import dtella_bridgeclient
except ImportError:
    dtella_bridgeclient = None

# TODO: Put a panic timer into sendMyStatus.
#       If any circumstances cause way too many status updates in a short time,
#       then flip out and put the node to sleep for a few minutes.

# TODO: notification of a remote nick collision

# TODO: Ping ack delay should affect the retransmit time for broadcasts?

# TODO: Make the sending of status updates more time conscious.

# TODO: Clean up duplicated code between DtellaMain and DtellaBridgeMain

# TODO: Might be able to get rid of the new_cb() mess.


# Miscellaneous Exceptions
class BadPacketError(Exception):
    pass

class BadTimingError(Exception):
    pass

class BadBroadcast(Exception):
    pass

class Reject(Exception):
    pass


# How many seconds our node will last without incoming pings
ONLINE_TIMEOUT = 30.0

# How many seconds our node will stay online without a DC client
NO_CLIENT_TIMEOUT = 60.0 * 5

# Reconnect time range.  Currently 10sec .. 15min
RECONNECT_RANGE = (10, 60*15)

NODE_EXPIRE_EXTEND = 15.0
PKTNUM_BUF = 20

# Status Flags
PERSIST_BIT = 0x1

# Ping Flags
IWANT_BIT = 0x01
GOTACK_BIT = 0x02
REQ_BIT = 0x04
ACK_BIT = 0x08
NBLIST_BIT = 0x10

# Broadcast Flags
REJECT_BIT = 0x1

# Ack flags
ACK_REJECT_BIT = 0x1

# Sync Flags
TIMEDOUT_BIT = 0x1

# Chat Flags
SLASHME_BIT = 0x1
NOTICE_BIT = 0x2

# ACK Modes
ACK_PRIVATE = 1
ACK_BROADCAST = 2


##############################################################################


class NickManager(object):

    def __init__(self, main):
        self.main = main
        self.nickmap = {}  # {nick.lower() -> Node}


    def getNickList(self):
        return [n.nick for n in self.nickmap.itervalues()]


    def lookupNick(self, nick):
        # Might raise KeyError
        return self.nickmap[nick.lower()]


    def removeNode(self, n, reason=""):
        try:
            if self.nickmap[n.nick.lower()] is not n:
                raise KeyError
        except KeyError:
            return

        del self.nickmap[n.nick.lower()]

        so = self.main.getStateObserver()

        if so:
            so.event_RemoveNick(n.nick, reason)


    def addNode(self, n):

        assert n.nick
        
        if n.nick.lower() in self.nickmap:
            return False

        self.nickmap[n.nick.lower()] = n

        so = self.main.getStateObserver()

        if so:
            so.event_AddNick(n.nick, n)
            so.event_UpdateInfo(n.nick, n.info)

        return True


    def setNodeInfo(self, n, info):

        if n.info == info:
            return

        n.info = info

        try:
            if self.nickmap[n.nick.lower()] is not n:
                raise KeyError
        except KeyError:
            return

        so = self.main.getStateObserver()

        if so:
            so.event_UpdateInfo(n.nick, n.info)
            

    def quitEverybody(self):
        # Tell DC client that everyone's gone

        so = self.main.getStateObserver()

        if so:
            for n in self.nickmap.itervalues():
                so.event_RemoveNick(n.nick, "Removing All Nicks")


##############################################################################


class PeerHandler(DatagramProtocol):

    def __init__(self, main):
        self.main = main
        self.remap_ip = None


    def sendPacket(self, data, addr):
        # Send a packet, optionally passing it through the encrypter
        # returns False if an error occurs
        
        print "sending %s to %s" % (data[:2], addr)
        data = self.main.pk_enc.encrypt(data)

        try:
            self.transport.write(data, addr)
        except socket.error:
            return False

        return True


    def datagramReceived(self, rawdata, addr, altport=False):

        ad = Ad().setAddrTuple(addr)

        # This will remap a router's internal IP to its external IP,
        # if the remapping is known.
        if self.remap_ip and ad.ip == self.remap_ip[0]:
            ad.orig_ip = ad.ip
            ad.ip = self.remap_ip[1]

        # Special handler for search results directly from DC
        if rawdata[:4] == '$SR ':
            self.handleDCSearchResult(ad, rawdata)
            return
        
        try:
            try:
                data = self.main.pk_enc.decrypt(rawdata)
            except ValueError, e:
                raise BadPacketError("Decrypt Failed: " + str(e))
            
            if len(data) < 2:
                raise BadPacketError("Too Short")

            kind = data[:2]

            if not kind.isalpha():
                raise BadPacketError("Kind not alphabetical")

            if altport:
                kind += "_alt"

            print "kind:", kind, "from:", addr, "data:", hexlify(data)

            # Make sure the sender's IP is permitted, but delay the check if
            # it's an initialize packet.
            if kind not in ('IQ', 'EC', 'IR', 'IC_alt'):
                if not ad.validate():
                    raise BadPacketError("Invalid source IP")

            try:
                method = getattr(self, 'handlePacket_%s' % kind)
            except AttributeError:
                raise BadPacketError("Unknown kind: %s" % kind)

            # arg1: Address the packet came from
            # arg2: The unencrypted packet
            method(ad, data)

        except BadPacketError, e:
            print "Bad Packet:", e
        except BadTimingError, e:
            print "Bad Timing:", e
        

    def decodePacket(self, fmt, data):

        if fmt[-1] == '+':
            fmt = fmt[:-1]
            size = struct.calcsize(fmt)
            rest = (data[size:],)
            data = data[:size]
        else:
            rest = ()

        try:
            parts = struct.unpack(fmt, data)
        except struct.error:
            raise BadPacketError("Can't decode packet")

        return parts + rest


    def decodeString1(self, data, factor=1):
        try:
            length, = struct.unpack('!B', data[:1])
        except struct.error:
            raise BadPacketError("Can't decode 1string")

        length *= factor

        if len(data) < 1+length:
            raise BadPacketError("Bad 1string length")

        return data[1:1+length], data[1+length:]


    def decodeString2(self, data):
        try:
            length, = struct.unpack('!H', data[:2])
        except struct.error:
            raise BadPacketError("Can't decode 2string")

        if length > 1024 or len(data) < 2+length:
            raise BadPacketError("Bad 2string length")

        return data[2:2+length], data[2+length:]


    def decodeChunkList(self, fmt, data):
        size = struct.calcsize(fmt)

        try:
            return [struct.unpack(fmt, data[i:i+size])
                    for i in range(0, len(data), size)]
        except struct.error:
            raise BadPacketError("Can't decode chunk list")


    def decodeNodeList(self, data):
        nbs, rest = self.decodeString1(data, 6)
        nbs = self.decodeChunkList('!6s', nbs)
        nbs = [ipp for ipp, in nbs if Ad().setRawIPPort(ipp).validate()]
        return nbs, rest


    def decodeNodeTimeList(self, data):
        nbs, rest = self.decodeString1(data, 6+4)
        nbs = [(ipp, age) for (ipp, age) in self.decodeChunkList('!6sI', nbs)
               if Ad().setRawIPPort(ipp).validate()]
        return nbs, rest


    def checkSource(self, src_ipp, ad):
        # Sometimes the source port number gets changed by NAT, but this
        # ensures that the source IP address matches the reported one.

        src_ad = Ad().setRawIPPort(src_ipp)

        if not src_ad.validate():
            raise BadPacketError("Invalid source IP")

        if src_ad.ip != ad.ip:
            raise BadPacketError("Source ip mismatch")

        # Callers of this function should make sure osm exists
        if src_ipp == self.main.osm.me.ipp:
            raise BadPacketError("Packet came from myself!?")

        self.main.state.refreshPeer(src_ad, 0)
        return src_ad


    def handleBroadcast(self, ad, data, check_cb):

        (kind, nb_ipp, hop, flags, src_ipp, rest
         ) = self.decodePacket('!2s6sBB6s+', data)

        osm = self.main.osm
        if not osm:
            raise BadTimingError("Not ready to route '%s' packet" % kind)

        # Make sure nb_ipp agrees with the sender's IP
        self.checkSource(nb_ipp, ad)

        # Make sure the src_ipp is valid
        src_ad = Ad().setRawIPPort(src_ipp)
        if not src_ad.validate():
            raise BadPacketError("Invalid forwarded source IP")

        # Make sure this came from one of my ping neighbors.
        # This helps a little to prevent the injection of random broadcast
        # traffic into the network.
        try:
            if not osm.lookup_ipp[nb_ipp].got_ack:
                raise KeyError
        except KeyError:
            raise BadTimingError("Broadcast packet not from a ping neighbor")

        ack_flags = 0

        # Check if we've seen this message before.
        ack_key = osm.mrm.generateKey(data)
        if osm.mrm.pokeMessage(ack_key, nb_ipp):
            
            # Ack and skip the rest
            self.sendAckPacket(nb_ipp, ACK_BROADCAST, ack_flags, ack_key)
            return

        # Get the source node object, if any
        try:
            src_n = osm.lookup_ipp[src_ipp]
        except KeyError:
            src_n = None

        # Callback the check_cb function
        try:
            new_cb = check_cb(src_n, src_ipp, rest)

        except BadBroadcast:
            # Mark that we've seen this message, but don't forward it.
            osm.mrm.newMessage(data, nb_ipp, tries=0)

            # Ack and skip the rest
            self.sendAckPacket(nb_ipp, ACK_BROADCAST, ack_flags, ack_key)
            return

        except Reject:
            # check_cb told us to reject this broadcast
            new_cb = None

            if src_ipp == nb_ipp:
                # If this is from a neighbor, just set the flag.
                # We'll send the ack later.
                ack_flags |= ACK_REJECT_BIT
                
            elif not (flags & REJECT_BIT):
                # Not from a neighbor, so send a reject packet immediately.
                self.sendAckPacket(
                    src_ipp, ACK_BROADCAST, ACK_REJECT_BIT, ack_key)

            # Set this flag to indicate to forwarded neighbors that we've
            # rejected the message.
            flags |= REJECT_BIT

        if hop > 0:
            # Start with the boradcast header
            packet = osm.mrm.broadcastHeader(kind, src_ipp, hop-1, flags)
           
            # Keep the rest of the message intact
            packet.append(rest)
        
            # Pass this message to MessageRoutingManager, so it will be
            # forwarded to all of my neighbors.
            osm.mrm.newMessage(''.join(packet), nb_ipp)

        # Ack the neighbor
        self.sendAckPacket(nb_ipp, ACK_BROADCAST, ack_flags, ack_key)

        # Update the original sender's age in the peer cache
        src_ad = Ad().setRawIPPort(src_ipp)
        self.main.state.refreshPeer(src_ad, 0)

        # Callback the new_cb function
        if new_cb:
            new_cb()


    def sendAckPacket(self, ipp, mode, flags, ack_key):
        packet = ['AK']
        packet.append(self.main.osm.me.ipp)
        packet.append(struct.pack("!BB", mode, flags))
        packet.append(ack_key)

        ad = Ad().setRawIPPort(ipp)
        self.main.ph.sendPacket(''.join(packet), ad.getAddrTuple())


    def isOutdatedStatus(self, n, pktnum):
        # This prevents a node's older status messages from taking
        # precedence over newer messages.

        if n is None:
            # Node doesn't exist, can't be outdated
            return False

        if n.bridge_data:
            # Don't allow updates for a bridge node
            return True
        
        if n.status_pktnum is None:
            # Don't have a pktnum yet, can't be outdated
            return False

        if 0 < (n.status_pktnum - pktnum) % 0x100000000 < PKTNUM_BUF:
            print "Outdated status update"
            return True

        return False


    def isMyStatus(self, src_ipp, pktnum, sendfull):
        # This makes corrections to any stray messages on the network that
        # would have an adverse effect on my current state.
        
        osm = self.main.osm

        # If it's not for me, nothing's wrong.
        if src_ipp != osm.me.ipp:
            return False

        # If it's old, ignore it.
        if 0 < (osm.me.status_pktnum - pktnum) % 0x100000000 < PKTNUM_BUF:
            print "Saw an outdated from-me packet"
            return True

        # If it's from my near future, then repair my packet number
        if 0 < (pktnum - osm.me.status_pktnum) % 0x100000000 < 2 * PKTNUM_BUF:
            osm.me.status_pktnum = pktnum

        # If I'm syncd, retransmit my status
        if osm.syncd:
            print "Reacting to an impersonated status."
            osm.sendMyStatus(sendfull)

        return True


    def handlePacket_IQ(self, ad, data):
        # Initialization Request; someone else is trying to get online
        (kind, myip, port
         ) = self.decodePacket('!2s4sH', data)

        if port == 0:
            raise BadPacketError("Zero Port")

        # The IPPort which is allegedly mine
        my_ad = Ad().setRawIP(myip)
        my_ad.port = self.main.state.udp_port

        # src_ad is supposed to be the sender node's "true external IPPort"
        src_ad = Ad()
        src_ad.port = port
        
        if ad.isRFC1918() and my_ad.validate():
            # If the request came from a private IP address, but was sent
            # toward a public IP address, then assume the sender node also
            # has the same public IP address.
            src_ad.ip = my_ad.ip
        else:
            src_ad.ip = ad.ip

        ip_valid = src_ad.validate()

        osm = self.main.osm
        state = self.main.state

        # Provide a max of 48 addresses in a normal response,
        # 8 addresses in a little cache response
        IR_LEN = 48
        IC_LEN = 8

        # Lists of stuff
        node_ipps = []
        ir_nodes = []
        ir_peercache = []
        ic_peercache = []

        if not ip_valid:
            # For invalid IPs, send no neighbors, and a small peercache
            # just so they can try for a second opinion.
            IR_LEN = IC_LEN
        
        elif osm:
            # Add in some online nodes
            node_ipps = [n.ipp for n in osm.nodes if n.expire_dcall]

            # Add myself
            node_ipps.append(osm.me.ipp)

            try:
                node_ipps = random.sample(node_ipps, IR_LEN)
            except ValueError:
                pass

        elif self.main.reconnect_dcall and my_ad.validate():
            # If we've recently failed to connect, then go online
            # as the sole node on the network.  Then report our node ipp
            # so this other node can try to join us.

            self.main.addMyIPReport(src_ad, my_ad)
            self.main.startNodeSync()

            osm = self.main.osm
            node_ipps = [osm.me.ipp]

        # Get my own IPP (if I know it)
        if osm:
            my_ipp = osm.me.ipp
        else:
            my_ipp = None

        now = time.time()

        # For each node, add its ip:port, and age.
        for ipp in node_ipps:
            if ipp == my_ipp:
                age = 0
            else:
                try:
                    age = max(now - state.peers[ipp], 0)
                except KeyError:
                    # If the entry has expired from the cache
                    # (not very likely), then assume 1 hour
                    age = 60*60

            ir_nodes.append(struct.pack('!6sI', ipp, age))

        # Convert node_ipps into a set, for O(1) lookups
        node_ipps = set(node_ipps)

        # Grab the youngest peers in our cache.
        for when,ipp in state.getYoungestPeers(IR_LEN):

            # Add packet data to the outlist
            age = max(now - when, 0)

            pc_entry = struct.pack('!6sI', ipp, age)

            if (len(node_ipps) + len(ir_peercache) < IR_LEN and
                    ipp not in node_ipps):
                ir_peercache.append(pc_entry)

            if len(ic_peercache) < IC_LEN:
                ic_peercache.append(pc_entry)

        # === IC response packet ===
        packet = ['IC']

        # My IPPort
        packet.append(my_ad.getRawIPPort())

        # Add 4-byte sender's IP address
        packet.append(src_ad.getRawIP())

        # Add 1-byte flag: 1 if IP is invalid
        packet.append(struct.pack('!B', int(not ip_valid)))

        # Add the peercache list
        packet.append(struct.pack('!B', len(ic_peercache)))
        packet.extend(ic_peercache)

        # Send IC packet to alternate port, undo NAT remapping
        if ad.orig_ip:
            ad.ip = ad.orig_ip
        self.sendPacket(''.join(packet), ad.getAddrTuple())
        

        # === IR response packet ===
        packet = ['IR']

        # My IPPort
        packet.append(my_ad.getRawIPPort())

        # Add to packet: 4-byte sender's IP address
        packet.append(src_ad.getRawIP())

        # Add 1-byte flag: 1 if IP is invalid
        packet.append(struct.pack('!B', int(not ip_valid)))

        # Add the node list
        packet.append(struct.pack('!B', len(ir_nodes)))
        packet.extend(ir_nodes)

        # Now add the peercache list
        packet.append(struct.pack('!B', len(ir_peercache)))
        packet.extend(ir_peercache)

        # Send IR packet to dtella port
        self.sendPacket(''.join(packet), src_ad.getAddrTuple())
       

        # Update the sender in my peer cache (if valid)
        self.main.state.refreshPeer(src_ad, 0)


    def handlePacket_IC_alt(self, ad, data):
        # Initialization Peer Cache (Alt port)

        (kind, src_ipp, myip, code, rest
         ) = self.decodePacket('!2s6s4sB+', data)

        src_ad = Ad().setRawIPPort(src_ipp)
        if ad.isRFC1918():
            if not src_ad.validate():
                raise BadPacketError("Invalid reported source IP")
        elif ad.validate():
            if src_ad.ip != ad.ip:
                raise BadPacketError("Source IP Mismatch")
        else:
            raise BadPacketError("Invalid source IP")

        pc, rest = self.decodeNodeTimeList(rest)

        if rest:
            raise BadPacketError("Extra data")

        if code not in (0,1):
            raise BadPacketError("Bad Response Code")

        if self.main.icm:
            self.main.icm.receivedInitResponse(src_ipp, myip, code, pc)


    def handlePacket_IR(self, ad, data):
        # Initialization Response
        (kind, src_ipp, myip, code, rest
         ) = self.decodePacket('!2s6s4sB+', data)

        src_ad = Ad().setRawIPPort(src_ipp)
        if ad.isRFC1918():
            if not src_ad.validate():
                raise BadPacketError("Invalid reported source IP")
        elif ad.validate():
            if src_ad.ip != ad.ip:
                raise BadPacketError("Source IP Mismatch")
        else:
            raise BadPacketError("Invalid source IP")

        # Node list, Peer Cache
        nd, rest = self.decodeNodeTimeList(rest)
        pc, rest = self.decodeNodeTimeList(rest)

        if rest:
            raise BadPacketError("Extra data")

        if code not in (0,1):
            raise BadPacketError("Bad Response Code")

        if self.main.icm:
            self.main.icm.receivedInitResponse(src_ipp, myip, code, pc, nd)
        else:
            raise BadPacketError("Not in initial connection mode")
        

    def handlePacket_NS(self, ad, data):
        # Broadcast: Node Status

        osm = self.main.osm

        def check_cb(src_n, src_ipp, rest):

            (pktnum, expire, sesid, uptime, flags, rest
             ) = self.decodePacket('!IH4sIB+', rest)

            nick, rest = self.decodeString1(rest)
            info, rest = self.decodeString1(rest)

            persist = bool(flags & PERSIST_BIT)

            if rest:
                raise BadPacketError("Extra data")

            if expire > 30*60:
                raise BadPacketError("Expire time > 30 minutes")
            
            # Make sure this isn't about me
            if self.isMyStatus(src_ipp, pktnum, sendfull=True):
                raise BadBroadcast
            
            if self.isOutdatedStatus(src_n, pktnum):
                raise BadBroadcast

            def new_cb():
                self.main.osm.refreshNodeStatus(
                    src_ipp, pktnum, expire, sesid, uptime,
                    persist, nick, info)

            return new_cb

        self.handleBroadcast(ad, data, check_cb)


    def handlePacket_NH(self, ad, data):
        # Broadcast: Node Status Hash (keep-alive)

        osm = self.main.osm

        def check_cb(src_n, src_ipp, rest):

            (pktnum, expire, infohash
             ) = self.decodePacket('!IH4s', rest)

            if expire > 30*60:
                raise BadPacketError("Expire timer > 30 minutes")
           
            # Make sure this isn't about me
            if self.isMyStatus(src_ipp, pktnum, sendfull=True):
                print "NH is impersonating me"
                raise BadBroadcast

            if self.isOutdatedStatus(src_n, pktnum):
                print "Outdated NH message"
                raise BadBroadcast

            def new_cb():
                src_n.status_pktnum = pktnum
                osm.scheduleNodeExpire(
                    src_n, expire + NODE_EXPIRE_EXTEND)

            if osm.syncd:
                if (src_n and src_n.expire_dcall and
                    src_n.infoHash() == infohash
                    ):
                    # We are syncd, and this node matches, so extend the
                    # expire timeout and keep forwarding.
                    return new_cb
            
            else:
                if not (src_n and src_n.expire_dcall):
                    # Not syncd, don't know enough about this node yet,
                    # so just forward blindly

                    # TODO: I think a race condition still exists here.
                    #       What if a sync reply arrives shortly after this,
                    #       with an expire time of a couple seconds?
                    
                    return None

                if src_n.infoHash() == infohash:
                    # We know about this node already, and the infohash
                    # matches, so extend timeout and keep forwarding
                    return new_cb

            raise Reject

        self.handleBroadcast(ad, data, check_cb)


    def handlePacket_NX(self, ad, data):
        # Broadcast: Node exiting

        osm = self.main.osm

        def check_cb(src_n, src_ipp, rest):

            (sesid,
             ) = self.decodePacket('!4s', rest)

            if src_n and src_n.bridge_data:
                print "Can't NX a bridge node"
                raise BadBroadcast

            if osm.syncd:
                if src_ipp == osm.me.ipp and sesid == osm.me.sesid:
                    print "Reacting to an NX"
                    # Yikes! Make me a new session id and rebroadcast it.
                    osm.me.sesid = randbytes(4)
                    for n in osm.nodes:
                        n.calcDistance(osm.me)
                    osm.nodes.sort()

                    osm.sendMyStatus()
                    osm.pgm.scheduleMakeNewLinks()
                    raise BadBroadcast

                if not (src_n and src_n.expire_dcall):
                    print "Got NX for not-online node"
                    raise BadBroadcast

                if sesid != src_n.sesid:
                    print "NX for wrong session id"
                    raise BadBroadcast

            elif not src_n:
                # Not syncd, and haven't seen this node yet.
                # Forward blindly
                return None

            def new_cb():
                osm.nodeExited(src_n, "Received NX")

            return new_cb

        self.handleBroadcast(ad, data, check_cb)


    def handlePacket_NF(self, ad, data):
        # Broadcast: Node failure

        osm = self.main.osm

        def check_cb(src_n, src_ipp, rest):

            (pktnum, sesid,
             ) = self.decodePacket('!I4s', rest)
            
            # Make sure this isn't about me
            if self.isMyStatus(src_ipp, pktnum, sendfull=False):
                raise BadBroadcast

            if not (src_n and src_n.expire_dcall):
                print "NF packet received for nonexistent node"
                raise BadBroadcast
            
            if src_n.sesid != sesid:
                print "NF has the wrong session ID"
                raise BadBroadcast
            
            if self.isOutdatedStatus(src_n, pktnum):
                print "NF is outdated"
                raise BadBroadcast

            def new_cb():
                # Reduce the expiration time.  If that node isn't actually
                # dead, it will rebroadcast a status update to correct it.
                
                if (dcall_timeleft(src_n.expire_dcall) > NODE_EXPIRE_EXTEND):
                    osm.scheduleNodeExpire(src_n, NODE_EXPIRE_EXTEND)
                    
            return new_cb

        self.handleBroadcast(ad, data, check_cb)


    def handlePacket_PF(self, ad, data):
        # Direct: Possible Falure (precursor to NF)

        osm = self.main.osm
        if not (osm and osm.syncd):
            raise BadTimingError("Not ready for PF")

        (kind, nb_ipp, dead_ipp, pktnum, sesid
         ) = self.decodePacket('!2s6s6sI4s', data)

        self.checkSource(nb_ipp, ad)

        try:
            n = osm.lookup_ipp[dead_ipp]
            if not n.expire_dcall:
                raise KeyError
        except KeyError:
            raise BadTimingError("PF received for not-online node")
        
        if n.sesid != sesid:
            raise BadTimingError("PF has the wrong session ID")
        
        if self.isOutdatedStatus(n, pktnum):
            raise BadTimingError("PF is outdated")

        osm.pgm.handleNodeFailure(n, nb_ipp)


    def handlePacket_CH(self, ad, data):
        # Broadcast: Chat message

        osm = self.main.osm

        def check_cb(src_n, src_ipp, rest):

            (pktnum, nhash, flags, rest
             ) = self.decodePacket('!I4sB+', rest)

            text, rest = self.decodeString2(rest)
            if rest:
                raise BadPacketError("Extra data")

            if src_ipp == osm.me.ipp:
                # Possibly a spoofed chat from me
                # TOOD: post some sort of warning?
                raise BadBroadcast

            if not osm.syncd:
                # Not syncd, forward blindly
                return None

            if src_n and src_n.bridge_data:
                raise BadBroadcast
            
            if src_n and src_n.expire_dcall and nhash == src_n.nickHash():
                
                def new_cb():
                    osm.cms.addMessage(src_ipp, pktnum,
                                       src_n.nick, text, flags)
                
                return new_cb

            raise Reject

        self.handleBroadcast(ad, data, check_cb)


    def handlePacket_TP(self, ad, data):
        # Broadcast: Set topic

        osm = self.main.osm

        def check_cb(src_n, src_ipp, rest):

            (pktnum, nhash, rest
             ) = self.decodePacket('!I4s+', rest)

            topic, rest = self.decodeString1(rest)
            if rest:
                raise BadPacketError("Extra data")

            if src_ipp == osm.me.ipp:
                # Weird...
                raise BadBroadcast

            if not osm.syncd:
                # Not syncd, forward blindly
                return None

            if src_n and src_n.bridge_data:
                # Bridge can't set the topic like this
                raise BadBroadcast
            
            if src_n and src_n.expire_dcall:
                
                def new_cb():
                    osm.tm.gotTopic(src_n, topic)
                
                return new_cb

            raise Reject

        self.handleBroadcast(ad, data, check_cb)
        

    def handlePacket_SQ(self, ad, data):
        # Broadcast: Search Request

        osm = self.main.osm

        def check_cb(src_n, src_ipp, rest):

            (pktnum, rest
             ) = self.decodePacket("!I+", rest)

            string, rest = self.decodeString1(rest)
            if rest:
                raise BadPacketError("Extra data")

            if src_ipp == osm.me.ipp:
                # A bit odd...
                raise BadBroadcast

            if src_n and src_n.bridge_data:
                raise BadBroadcast

            if not osm.syncd:
                # Not syncd, forward blindly
                return None

            if src_n and src_n.expire_dcall:
                # Looks good

                def new_cb():
                    dch = self.main.getOnlineDCH()

                    if dch:
                        dch.pushSearchRequest(src_ipp, string)
                
                return new_cb

            raise Reject

        self.handleBroadcast(ad, data, check_cb)


    def handlePacket_AK(self, ad, data):
        # Direct: Acknowledgement

        osm = self.main.osm
        if not osm:
            raise BadTimingError("Not ready for AK packet")

        (kind, src_ipp, mode, flags, ack_key
         ) = self.decodePacket('!2s6sBB8s', data)

        self.checkSource(src_ipp, ad)

        reject = bool(flags & ACK_REJECT_BIT)

        if mode == ACK_PRIVATE:
            # Handle a private message ack
            
            if not osm.syncd:
                raise BadTimingError("Not ready for PM AK packet")

            try:
                n = osm.lookup_ipp[src_ipp]
            except KeyError:
                raise BadTimingError("AK: Unknown PM ACK node")
            else:
                n.receivedPrivateMessageAck(ack_key, reject)

        elif mode == ACK_BROADCAST:
            # Handle a broadcast ack

            if osm.syncd and reject:
                osm.mrm.receivedRejection(ack_key)

            # Tell MRM to stop retransmitting message to this neighbor
            osm.mrm.pokeMessage(ack_key, src_ipp)

        else:
            raise BadPacketError("Unknown AK mode")


    def handlePacket_CA(self, ad, data):
        # Direct: ConnectToMe

        (kind, src_ipp, ack_key, src_nhash, dst_nhash, port
         ) = self.decodePacket('!2s6s8s4s4sH', data)

        osm = self.main.osm
        if not (osm and osm.syncd):
            raise BadTimingError("Not ready for CA")

        self.checkSource(src_ipp, ad)

        osm.pmm.receivedMessage(kind, src_ipp, ack_key,
                                src_nhash, dst_nhash, port)


    def handlePacket_CP(self, ad, data):
        # Direct: RevConnectToMe

        (kind, src_ipp, ack_key, src_nhash, dst_nhash
         ) = self.decodePacket('!2s6s8s4s4s', data)

        osm = self.main.osm
        if not (osm and osm.syncd):
            raise BadTimingError("Not ready for CP")

        self.checkSource(src_ipp, ad)

        osm.pmm.receivedMessage(kind, src_ipp, ack_key,
                                src_nhash, dst_nhash)


    def handlePacket_PM(self, ad, data):
        # Direct: Private Message

        (kind, src_ipp, ack_key, src_nhash, dst_nhash, flags, rest
         ) = self.decodePacket('!2s6s8s4s4sB+', data)

        osm = self.main.osm
        if not (osm and osm.syncd):
            raise BadTimingError("Not ready for PM")

        self.checkSource(src_ipp, ad)

        text, rest = self.decodeString2(rest)

        if rest:
            raise BadPacketError("Extra data")

        notice = bool(flags & NOTICE_BIT)

        osm.pmm.receivedMessage(kind, src_ipp, ack_key,
                                src_nhash, dst_nhash, notice, text)


    def handlePacket_YT(self, ad, data):
        # Direct: Sync Topic

        (kind, src_ipp, ack_key, rest
         ) = self.decodePacket('!2s6s8s+', data)

        osm = self.main.osm
        if not (osm and osm.syncd):
            raise BadTimingError("Not ready for YT")

        self.checkSource(src_ipp, ad)

        topic, rest = self.decodeString1(rest)

        if rest:
            raise BadPacketError("Extra data")

        osm.tm.gotSyncTopic(src_ipp, ack_key, topic)


    def handlePacket_PG(self, ad, data):
        # Direct: Local Ping

        osm = self.main.osm
        if not osm:
            raise BadTimingError("Not ready to receive pings yet")

        (kind, src_ipp, flags, rest
         ) = self.decodePacket('!2s6sB+', data)

        self.checkSource(src_ipp, ad)

        uwant =     bool(flags & IWANT_BIT)
        u_got_ack = bool(flags & GOTACK_BIT)
        req =       bool(flags & REQ_BIT)
        ack =       bool(flags & ACK_BIT)
        nblist =    bool(flags & NBLIST_BIT)

        if req:
            req_key, rest = self.decodePacket('!4s+', rest)
        else:
            req_key = None

        if ack:
            ack_key, rest = self.decodePacket('!4s+', rest)
        else:
            ack_key = None

        if nblist:
            # Get neighbor list
            nbs, rest = self.decodeNodeList(rest)
            if len(nbs) > 8:
                raise BadPacketError("Too many neighbors")

            if len(set(nbs)) != len(nbs):
                raise BadPacketError("Neighbors not all unique")
        else:
            nbs = None

        if rest:
            raise BadPacketError("Extra Data")

        osm.pgm.receivedPing(src_ipp, uwant, u_got_ack, req_key, ack_key, nbs)


    def handlePacket_YQ(self, ad, data):
        # Sync Request

        (kind, nb_ipp, hop, flags, src_ipp, sesid
         ) = self.decodePacket('!2s6sBB6s4s', data)

        osm = self.main.osm
        if not (osm and osm.syncd):
            raise BadTimingError("Not ready to handle a sync request")

        self.checkSource(nb_ipp, ad)
        
        timedout = bool(flags & TIMEDOUT_BIT)
        
        if not 0 <= hop <= 2:
            raise BadPacketError("Bad hop count")

        elif hop == 2 and src_ipp != nb_ipp:
            raise BadPacketError("Source ip mismatch")

        # Decrease hop count, and call handler
        osm.yqrm.receivedSyncRequest(nb_ipp, src_ipp, sesid, hop, timedout)


    def handlePacket_YR(self, ad, data):
        # Sync Reply

        osm = self.main.osm
        if not osm:
            raise BadTimingError("Not ready for sync reply")

        (kind, src_ipp, pktnum, expire, sesid, uptime, flags, rest
         ) = self.decodePacket('!2s6sIH4sIB+', data)

        self.checkSource(src_ipp, ad)

        persist = bool(flags & PERSIST_BIT)

        nick, rest = self.decodeString1(rest)
        info, rest = self.decodeString1(rest)

        c_nbs, rest = self.decodeNodeList(rest)
        u_nbs, rest = self.decodeNodeList(rest)

        if rest:
            raise BadPacketError("Extra data")

        if expire > 30*60:
            raise BadPacketError("Expire time > 30 minutes")

        try:
            n = osm.lookup_ipp[src_ipp]
        except KeyError:
            n = None

        # Check for outdated status, in case an NS already arrived.
        if not self.isOutdatedStatus(n, pktnum):
            osm.refreshNodeStatus(
                src_ipp, pktnum, expire, sesid, uptime, persist, nick, info)

        if osm.sm:
            osm.sm.receivedSyncReply(src_ipp, c_nbs, u_nbs)


    def handlePacket_EC(self, ad, data):
        # Login echo

        osm = self.main.osm
        if not osm:
            raise BadTimingError("Not ready for login echo")

        (kind, rand
         ) = self.decodePacket('!2s8s', data)

        osm.receivedLoginEcho(ad, rand)


    searchreply_re = re.compile(r"^\$SR ([^ ]+) (.*) \([^ ]+\)\|?$")
    
    def handleDCSearchResult(self, ad, data):
        # UDP search reply packet came directly from another DC client

        if not ad.validate():
            print "Search result from invalid IP"
            return

        m = self.searchreply_re.match(data)

        if not m:
            print "Search doesn't match pattern"
            return

        nick = m.group(1)
        data = m.group(2)

        if '|' in nick or '|' in data:
            print "Search result contains a pipe"
            return

        dch = self.main.getOnlineDCH()
        if not dch:
            return

        if nick == dch.nick:
            nick = dch.bot.nick

        # TODO: Don't hard-code port 7314
        data = "$SR %s %s (127.0.0.1:7314)" % (nick, data)

        dch.sendLine(data)
        


##############################################################################


class InitialContactManager(DatagramProtocol):
    # Scans through a list of known IP:Ports, and send a small ping to a
    # bunch of them.  Collect addresses of known online peers, and eventually
    # Pass off the list to the neighbor connection manager.


    class PeerInfo(object):
        __lt__ = lambda self,other: self.seen >  other.seen
        __le__ = lambda self,other: self.seen >= other.seen
        
        def __init__(self, ipp, seen, inheap=False):
            self.ipp = ipp
            self.seen = seen
            self.inheap = inheap
            self.timeout_dcall = None
            
            self.alt_reply = False
            self.bad_ip = False

    
    def __init__(self, main, cb):
        self.main = main
        self.done_callback = cb

        self.main.showLoginStatus("Scanning For Online Nodes...",
                                  counter=1)

        # Listen on an arbitrary UDP port
        try:
            reactor.listenUDP(0, self)
        except socket.error:
            # If for whatever reason it fails, just try to get by without
            # the alternate port.
            print "Failed to bind alternate UDP Port"

        self.peers = {}  # {IPPort -> PeerInfo object}

        for ipp, seen in self.main.state.peers.iteritems():
            self.peers[ipp] = self.PeerInfo(ipp, seen, inheap=True)

        self.heap = self.peers.values()
        heapq.heapify(self.heap)

        self.waitreply = set()

        self.node_ipps = set()

        self.initrequest_dcall = None
        self.finish_dcall = None

        self.stats_bad_ip = 0       # How many bad IPs reported
        self.stats_dead_port = 0    # How many no-port-forwards found
        self.stats_good = 0         # How many neighbor lists given

        self.scheduleInitRequest()


    def newPeer(self, ipp, seen):
        # Called by PeerAddressManager
        
        p = self.PeerInfo(ipp, seen)
        self.peers[ipp] = p
        heapq.heappush(self.heap, p)
        self.scheduleInitRequest()


    def youngerPeer(self, ipp, seen):
        # Called by PeerAddressManager
        
        p = self.peers[ipp]
        p.seen = seen
        
        # Bubble it up the heap.
        # This takes O(n) and uses an undocumented heapq function...
        if p.inheap:
            heapq._siftdown(self.heap, 0, self.heap.index(p))


    def scheduleInitRequest(self):
        if self.initrequest_dcall:
            return

        def cb():
            self.initrequest_dcall = None

            try:
                p = heapq.heappop(self.heap)
            except IndexError:
                self.doneCheck()
                return

            p.inheap = False

            ad = Ad().setRawIPPort(p.ipp)

            packet = ['IQ']
            packet.append(ad.getRawIP())
            packet.append(struct.pack('!H', self.main.state.udp_port))

            print "sending IQ to %s" % (ad.getAddrTuple(),)

            packet = self.main.pk_enc.encrypt(''.join(packet))

            try:
                # Send from the alternate port
                self.transport.write(packet, ad.getAddrTuple())
            except (AttributeError, socket.error):
                pass
            else:
                self.waitreply.add(p)
                self.schedulePeerContactTimeout(p)
            
            self.initrequest_dcall = reactor.callLater(0.05, cb)

        self.initrequest_dcall = reactor.callLater(0, cb)


    def doneCheck(self):
        # If there's nothing left to ping, and nobody waiting for replies,
        # then make do with what we have.
        if not (self.heap or self.waitreply):
            print "Nothing to ping, nothing waiting"
            self.shutdown()
            self.done_callback()


    def schedulePeerContactTimeout(self, p):
        
        def cb(p):
            print "peerContactTimeout"
            p.timeout_dcall = None
            self.waitreply.discard(p)

            if p.alt_reply:
                self.recordResultType('dead_port')
            
            self.doneCheck()

        p.timeout_dcall = reactor.callLater(5.0, cb, p)


    def receivedInitResponse(self, src_ipp, myip, code, pc, nd=None):

        print "init response", hexlify(myip), code

        try:
            p = self.peers[src_ipp]
        except KeyError:
            raise BadPacketError("Didn't ask for this response")

        if nd is None:
            # IC packet

            # Ignore if we've already gotten one, or if
            # The IR has already arrived, or expired.
            if p.alt_reply or p.timeout_dcall is None:
                return

            p.alt_reply = True
            
        else:
            # IR packet
            try:
                self.waitreply.remove(p)
            except KeyError:
                # Wasn't waiting for this reply
                return
    
            dcall_discard(p, 'timeout_dcall')

        # Add some new peers to our cache
        if pc:
            for ipp, age in pc:
                ad = Ad().setRawIPPort(ipp)
                self.main.state.refreshPeer(ad, age)

        # Get my own IP address
        my_ad = Ad().setRawIP(myip)

        # Check if they reported a bad IP
        if code == 1:
            if not p.bad_ip:
                p.bad_ip = True
                self.recordResultType('bad_ip')
            return

        # Add my own IP to the list
        src_ad = Ad().setRawIPPort(src_ipp)
        self.main.addMyIPReport(src_ad, my_ad)

        # Add the node who sent this packet to the cache
        self.main.state.refreshPeer(src_ad, 0)

        # If this is an IC packet, stop here.
        if nd is None:
            return

        # Add to set of currently online nodes
        if nd:
            for ipp, age in nd:

                ad = Ad().setRawIPPort(ipp)

                # Add to the peer cache
                self.main.state.refreshPeer(ad, age)

                # Add to set of probably-active nodes
                self.node_ipps.add(ipp)

            self.recordResultType('good')

        # Check if there's nothing left to do
        self.doneCheck()


    def recordResultType(self, kind):

        print "recordResultType:", kind

        # After we get a meaningful packet, stop after 5 seconds.

        if kind == 'good':
            self.stats_good += 1

            if self.stats_good == 1:
                # On the first good reply, stop after 5 seconds
                self.scheduleFinish(5)
            elif self.stats_good == 5:
                # After 5 good replies, stop now
                self.scheduleFinish(0)
            
        elif kind == 'bad_ip':
            self.stats_bad_ip += 1

            if self.stats_bad_ip == 1:
                # On the first bad_ip reply, stop after 10 seconds
                self.scheduleFinish(10)

        elif kind == 'dead_port':
            self.stats_dead_port += 1

            if self.stats_dead_port == 1:
                # On the first dead_port reply, stop after 10 seconds
                self.scheduleFinish(10)

        else:
            assert False


    def scheduleFinish(self, when):
        # Set up a timer for early termination

        if self.finish_dcall:
            if when < dcall_timeleft(self.finish_dcall):
                self.finish_dcall.reset(when)
            return

        def cb():
            self.finish_dcall = None
            self.shutdown()
            self.done_callback()

        self.finish_dcall = reactor.callLater(when, cb)


    def datagramReceived(self, data, addr):
        # Let the main PeerHandler take care of decoding packets sent
        # to the alternate UDP port.
        self.main.ph.datagramReceived(data, addr, altport=True)


    def shutdown(self):
        # Cancel all dcalls
        dcall_discard(self, 'initrequest_dcall')
        dcall_discard(self, 'finish_dcall')

        for p in self.peers.values():
            dcall_discard(p, 'timeout_dcall')

        # Close socket
        if self.transport:
            self.transport.stopListening()


##############################################################################


class Node(object):
    __lt__ = lambda self,other: self.dist <  other.dist
    __le__ = lambda self,other: self.dist <= other.dist

    def __init__(self, ipp):
        # Dtella Tracking stuff
        self.ipp = ipp            # 6-byte IP:Port
        self.sesid = None         # 4-byte session ID
        self.dist = None          # 16-byte md5 "distance"
        self.inlist = False       # True if it's in the nodes list
        self.expire_dcall = None  # dcall for expiring stale nodes
        self.status_pktnum = None # Pktnum of last status update

        # ack_key -> timeout DelayedCall
        self.msgkeys_out = {}
        self.msgkeys_in = {}

        # Ping stuff
        self.reqs = {}                # {ack_key: time sent}
        self.sendPing_dcall = None    # dcall for sending pings
        self.nodeFail_dcall = None    # keep track of node failure
        self.got_ack = False
        self.u_got_ack = False
        self.ping_nbs = None

        # General Info
        self.nick = ''
        self.info = ''
        self.uptime = 0.0
        self.persist = False

        # If this is a bridge node, store extra details here
        self.bridge_data = None


    def calcDistance(self, me):
        # Distance is pseudo-random, to keep the network spread out

        my_key = me.ipp + me.sesid
        nb_key = self.ipp + self.sesid

        if my_key <= nb_key:
            self.dist = md5.new(my_key + nb_key).digest()
        else:
            self.dist = md5.new(nb_key + my_key).digest()


    def nickHash(self):
        # Return a 4-byte hash to prevent a transient nick mismapping
        
        if self.nick:
            return md5.new(self.ipp + self.sesid + self.nick).digest()[:4]
        else:
            return None


    def flags(self):
        flags = (self.persist and PERSIST_BIT)
        return struct.pack('!B', flags)


    def infoHash(self):
        # Return a 4-byte hash of the current node status

        # TODO: put a separator between nick+info
        
        return md5.new(self.sesid + self.flags() +
                       self.nick + '|' + self.info).digest()[:4]


    def getPMAckKey(self):
        # Generate random packet ID for messages going TO this node
        while 1:
            ack_key = randbytes(8)
            if ack_key not in self.msgkeys_out:
                break

        return ack_key


    def pokePMKey(self, ack_key):
        # Schedule expiration of a PM ack key, for messages we
        # receive _FROM_ this node.

        # Return True if this is a new key
    
        try:
            self.msgkeys_in[ack_key].reset(60.0)
            return False

        except KeyError:
            def cb():
                self.msgkeys_in.pop(ack_key)
            self.msgkeys_in[ack_key] = reactor.callLater(60.0, cb)
            return True
    


    def cancelPrivMsgs(self):
        # Cancel all pending privmsg timeouts

        for dcall in self.msgkeys_in.itervalues():
            dcall.cancel()
        
        for dcall in self.msgkeys_out.itervalues():
            dcall.cancel()

        self.msgkeys_in.clear()
        self.msgkeys_out.clear()


    def sendPrivateMessage(self, ph, ack_key, packet, fail_cb):
        # Send an ACK-able direct message to this node

        def cb(fail_cb, tries):

            if tries == 0:
                del self.msgkeys_out[ack_key]
                fail_cb()
                return

            ad = Ad().setRawIPPort(self.ipp)
            ph.sendPacket(packet, ad.getAddrTuple())

            # Set timeout for outbound message
            # This will be cancelled if we receive an AK in time.
            self.msgkeys_out[ack_key] = reactor.callLater(
                1.0, cb, fail_cb, tries-1)

        # Send it 3 times, then fail.
        cb(fail_cb, 3)


    def receivedPrivateMessageAck(self, ack_key, reject):
        # Got an ACK for a private message

        try:
            dcall = self.msgkeys_out.pop(ack_key)
        except KeyError:
            return

        if reject:
            dcall.args[0]()  # Call fail_cb

        dcall.cancel()


    def stillAlive(self):
        # return True if the connection hasn't timed out yet
        return (self.sendPing_dcall and self.sendPing_dcall.args[1] >= 0)


    def stronglyConnected(self):
        # return True if both ends are willing to accept broadcast traffic
        return (self.got_ack and self.u_got_ack)


    def event_PrivateMessage(self, main, text, fail_cb):

        osm = main.osm

        if len(text) > 1024:
            text = text[:1024-12] + ' [Truncated]'

        flags = 0

        ack_key = self.getPMAckKey()

        packet = ['PM']
        packet.append(osm.me.ipp)
        packet.append(ack_key)
        packet.append(osm.me.nickHash())
        packet.append(self.nickHash())
        packet.append(struct.pack('!BH', flags, len(text)))
        packet.append(text)
        packet = ''.join(packet)

        self.sendPrivateMessage(main.ph, ack_key, packet, fail_cb)


    def event_ConnectToMe(self, main, port, fail_cb):

        osm = main.osm

        ack_key = self.getPMAckKey()

        packet = ['CA']
        packet.append(osm.me.ipp)
        packet.append(ack_key)
        packet.append(osm.me.nickHash())
        packet.append(self.nickHash())
        packet.append(struct.pack('!H', port))
        packet = ''.join(packet)

        self.sendPrivateMessage(main.ph, ack_key, packet, fail_cb)


    def event_RevConnectToMe(self, main, fail_cb):

        osm = main.osm

        ack_key = self.getPMAckKey()

        packet = ['CP']
        packet.append(osm.me.ipp)
        packet.append(ack_key)
        packet.append(osm.me.nickHash())
        packet.append(self.nickHash())
        packet = ''.join(packet)

        self.sendPrivateMessage(main.ph, ack_key, packet, fail_cb)


    def shutdown(self):
        dcall_discard(self, 'expire_dcall')
        
        self.cancelPrivMsgs()
        
        if self.bridge_data:
            self.bridge_data.shutdown()


class MeNode(Node):
    def event_PrivateMessage(self, main, text, fail_cb):
        dch = main.dch
        dch.pushPrivMsg(dch.nick, text)

    def event_ConnectToMe(self, main, port, fail_cb):
        fail_cb()

    def event_RevConnectToMe(self, main, fail_cb):
        fail_cb()



##############################################################################

            
class SyncManager(object):

    class SyncInfo(object):
        def __init__(self, ipp):
            self.ipp = ipp
            self.timeout_dcall = None
            self.fail_limit = 2

            # Used for stats
            self.in_total = False
            self.in_done = False

    def __init__(self, main):
        self.main = main
        self.uncontacted = RandSet()
        self.waitcount = 0
        self.info = {}

        for n in self.main.osm.nodes:
            s = self.info[n.ipp] = self.SyncInfo(n.ipp)
            s.in_total = True
            self.uncontacted.add(n.ipp)

        self.syncRequest_dcall = None
        self.scheduleSyncRequest()

        # Keep stats for how far along we are
        self.stats_done = 0
        self.stats_total = len(self.main.osm.nodes)
        self.stats_lastbar = -1

        self.main.showLoginStatus("Network Sync In Progress...",
                                  counter='inc')

        self.showProgress_dcall = None
        self.showProgress()


    def updateStats(self, s, done, total):
        # Update the sync statistics for a single node.
        if done > 0 and not s.in_done:
            s.in_done = True
            self.stats_done += 1
        elif done < 0 and s.in_done:
            s.in_done = False
            self.stats_done -= 1
            
        if total > 0 and not s.in_total:
            s.in_total = True
            self.stats_total += 1
        elif total < 0 and s.in_total:
            s.in_total = False
            self.stats_total -= 1


    def showProgress(self):
        # Notify the user of the sync stats, if they've changed.

        MAX = 20

        def cb(bar, done, total):
            self.showProgress_dcall = None

            if bar == self.stats_lastbar:
                return

            self.stats_lastbar = bar

            progress = '>'*bar + '_'*(MAX-bar)
            self.main.showLoginStatus("[%s] (%d/%d)" % (
                progress, done, total))

        if self.stats_total == 0:
            bar = MAX
        else:
            bar = (MAX * self.stats_done) // self.stats_total

        dcall_discard(self, 'showProgress_dcall')

        if bar == MAX:
            # The final update should draw immediately
            cb(bar, self.stats_done, self.stats_total)
        else:
            # Otherwise, only draw once per reactor loop
            self.showProgress_dcall = reactor.callLater(
                0, cb, bar, self.stats_done, self.stats_total)


    def scheduleSyncRequest(self):
        if self.syncRequest_dcall:
            return

        def cb():
            self.syncRequest_dcall = None
            
            try:
                # Grab an arbitrary (semi-pseudorandom) uncontacted node.
                ipp = self.uncontacted.pop()
            except KeyError:
                # Ran out of nodes; see if we're done yet.
                self.doneCheck()
                return

            s = self.info[ipp]

            osm = self.main.osm
            ph = self.main.ph

            hops = 2
            flags = (s.fail_limit < 2) and TIMEDOUT_BIT

            # Send the sync request
            packet = osm.mrm.broadcastHeader('YQ', osm.me.ipp, hops, flags)
            packet.append(osm.me.sesid)
            
            ad = Ad().setRawIPPort(s.ipp)
            ph.sendPacket(''.join(packet), ad.getAddrTuple())

            self.scheduleSyncTimeout(s)

            # TODO: To make syncing faster on large networks, this interval
            #       should be controlled by some sort of rate
            #       detecting/limiting algorithm.
            self.syncRequest_dcall = reactor.callLater(0.1, cb)

        self.syncRequest_dcall = reactor.callLater(0.1, cb)


    def doneCheck(self):
        if not self.uncontacted and self.waitcount == 0:
            dcall_discard(self, 'syncRequest_dcall')
            dcall_discard(self, 'showProgress_dcall')
            self.main.osm.syncComplete()


    def giveUpNode(self, ipp):
        # This node seems to have left the network, so don't contact it.
        try:
            s = self.info.pop(ipp)
        except KeyError:
            return

        self.uncontacted.discard(ipp)

        self.cancelSyncTimeout(s)

        self.updateStats(s, -1, -1)
        self.showProgress()


    def receivedSyncReply(self, src_ipp, c_nbs, u_nbs):

        my_ipp = self.main.osm.me.ipp

        # Loop through all the nodes that were just contacted by proxy
        for ipp in c_nbs:
            if ipp == my_ipp:
                continue
            try:
                s = self.info[ipp]
            except KeyError:
                # Haven't seen this one before, set a timeout because
                # we should be hearing a reply.
                s = self.info[ipp] = self.SyncInfo(ipp)
                self.scheduleSyncTimeout(s)
            else:
                if ipp in self.uncontacted:
                    # Seen this node, had planned to ping it later.
                    # Pretend like we just pinged it now.
                    self.uncontacted.discard(ipp)
                    self.scheduleSyncTimeout(s)

            self.updateStats(s, 0, +1)

        # Loop through all the nodes which weren't contacted by this
        # host, but that the host is neighbors with.
        for ipp in u_nbs:
            if ipp == my_ipp:
                continue
            if ipp not in self.info:
                # If we haven't heard of this node before, create some
                # info and plan on pinging it later
                s = self.info[ipp] = self.SyncInfo(ipp)

                self.uncontacted.add(ipp)
                self.scheduleSyncRequest()

                self.updateStats(s, 0, +1)


        # Mark off that we've received a reply.
        try:
            s = self.info[src_ipp]
        except KeyError:
            s = self.info[src_ipp] = self.SyncInfo(src_ipp)

        self.uncontacted.discard(src_ipp)

        self.updateStats(s, +1, +1)
        self.showProgress()

        self.cancelSyncTimeout(s)


    def scheduleSyncTimeout(self, s):
        if s.timeout_dcall:
            return

        def cb(s):
            s.timeout_dcall = None
            self.waitcount -= 1

            s.fail_limit -= 1
            if s.fail_limit > 0:
                # Try again
                self.uncontacted.add(s.ipp)
                self.scheduleSyncRequest()
            else:
                self.updateStats(s, 0, -1)
                self.showProgress()

                # Don't try anymore
                self.doneCheck()

        self.waitcount += 1
        s.timeout_dcall = reactor.callLater(3.5, cb, s)


    def cancelSyncTimeout(self, s):
        if s.timeout_dcall:
            dcall_discard(s, 'timeout_dcall')
            self.waitcount -= 1
            self.doneCheck()


    def shutdown(self):
        # Cancel all timeouts

        dcall_discard(self, 'syncRequest_dcall')
        dcall_discard(self, 'showProgress_dcall')

        for s in self.info.values():
            dcall_discard(s, 'timeout_dcall')


##############################################################################
        

class OnlineStateManager(object):

    def __init__(self, main, my_ipp, node_ipps, bcm=None, bsm=None):
        self.main = main
        self.main.osm = self
        self.syncd = False

        # Don't allow myself in the nodes list
        if node_ipps:
            node_ipps.discard(my_ipp)

        # Create a Node for me
        self.me = MeNode(my_ipp)
        self.me.sesid = randbytes(4)
        self.me.uptime = seconds()

        # NickManager
        self.nkm = NickManager(main)

        # MessageRoutingManager
        self.mrm = MessageRoutingManager(main)

        # PingManager
        self.pgm = PingManager(main)

        # TopicManager
        self.tm = TopicManager(main)

        # BridgeClientManager / BridgeServerManager
        self.bcm = bcm
        self.bsm = bsm

        # SyncManager (init after contacting the first neighbor)
        self.sm = None

        # Init all these when sync is established:
        self.yqrm = None        # SyncRequestRoutingManager
        self.cms = None         # ChatMessageSequencer
        self.pmm = None         # PrivateMessageManager
        
        self.sendStatus_dcall = None

        self.sendLoginEcho()

        self.lookup_ipp = weakref.WeakValueDictionary() # {ipp: Node()}
        self.nodes = []

        for ipp in node_ipps:
            n = self.lookup_ipp[ipp] = Node(ipp)
            n.inlist = True
            self.pgm.cancelInactiveLink(n)
            
            self.nodes.append(n)

        # Initially, we'll just connect to random nodes.
        # This list will be sorted after syncing is finished.
        random.shuffle(self.nodes)

        # TODO: DEBUG
        self.printNodes()

        if self.nodes:
            self.main.showLoginStatus("Joining The Network.",
                                      counter='inc')
            self.pgm.scheduleMakeNewLinks()
        else:
            self.main.showLoginStatus("Creating a new empty network.",
                                      counter='inc')
            self.syncComplete()


    def printNodes(self):

        self.printNodes_dcall = None

        def cb():
        
            print "--Nodes--"
            for n in self.nodes + [self.me]:
                expire = -1
                if n.expire_dcall:
                    expire = dcall_timeleft(n.expire_dcall)
                    
                print "> %s: expire=%d nick='%s'" % (
                    hexlify(n.ipp),
                    expire,
                    n.nick
                    )

            print "len(lookup_ipp):", len(self.lookup_ipp)

            self.printNodes_dcall = reactor.callLater(10, cb)

        self.printNodes_dcall = reactor.callLater(0, cb)


    def syncComplete(self):

        # Forget the SyncManager
        self.sm = None

        # Remove weird neighbors from the list, and sort by distance
        nodes = []
        for n in self.nodes:
            n.inlist = bool(n.expire_dcall)
            if n.inlist:
                n.calcDistance(self.me)
                nodes.append(n)
            else:
                # No longer an outbound node
                self.pgm.removeOutboundLink(n)
 
        self.nodes = nodes
        self.nodes.sort()

        # Get ready to handle Sync requests from other nodes
        self.yqrm = SyncRequestRoutingManager(self.main)
        self.cms = ChatMessageSequencer(self.main)
        self.pmm = PrivateMessageManager(self.main)
        self.syncd = True

        if self.bsm:
            self.bsm.syncComplete()

        # Connect to the "closest" neighbors
        self.pgm.scheduleMakeNewLinks()

        self.updateMyInfo(send=True)

        # Maybe send the full user list to the DC client
        dch = self.main.getOnlineDCH()
        if dch:
            dch.d_GetNickList()
            dch.grabDtellaTopic()

        self.main.showLoginStatus("Sync Complete; You're Online!",
                                  counter='inc')


    def refreshNodeStatus(self, src_ipp, pktnum, expire, sesid, uptime,
                          persist, nick, info):
        try:
            n = self.lookup_ipp[src_ipp]
        except KeyError:
            n = self.lookup_ipp[src_ipp] = Node(src_ipp)

        print "refreshNodeStatus: ipp=%s pktnum=? expire=%d sesid=%s uptime=%d persist=%d nick=%s info=%s" % (
            hexlify(src_ipp), expire, hexlify(sesid),
            uptime, persist, nick, info)

        # Update the last-seen status packet number
        n.status_pktnum = pktnum

        # Change uptime to a fixed time when the node went up
        uptime = seconds() - uptime

        if self.syncd and n.inlist and n.sesid != sesid:
            # session ID changed; remove n from sorted nodes list
            # so that it will be reinserted into the correct place
            del self.nodes[bisect.bisect_left(self.nodes, n)]
            n.inlist = False

        # Update info
        n.sesid = sesid
        n.uptime = uptime
        n.persist = persist

        # If there's no nick, then don't bother with info either
        if not nick:
            info = ''

        if nick != n.nick:
            if n.nick:
                self.nkm.removeNode(n, "Status Changed")
                n.nick = n.info = ''

            n.nick = nick
            n.info = info

            reason = validateNick(n.nick)
            if reason:
                # TODO: report
                n.nick = n.info = ''
                print "Nick '%s' did not validate!" % n.nick

            elif n.nick:
                if not self.nkm.addNode(n):
                    # TODO: report
                    n.nick = n.info = ''
                    print "Nick collision for '%s'" % n.nick

        else:
            self.nkm.setNodeInfo(n, info)

        # If n isn't in nodes list, then add it
        if not n.inlist:
            if self.syncd:
                n.calcDistance(self.me)
                bisect.insort(self.nodes, n)
            else:
                self.nodes.append(n)
            n.inlist = True

        # Tell the topic manager if a new node signs on
        if self.syncd and not n.expire_dcall:
            self.tm.checkNewNode(n)

        # Expire this node after the expected retransmit
        self.scheduleNodeExpire(n, expire + NODE_EXPIRE_EXTEND)

        # Possibly make this new node an outgoing link
        self.pgm.scheduleMakeNewLinks()

        # Return the node
        return n


    def nodeExited(self, n, reason=""):
        # Node n dropped off the network

        dcall_discard(n, 'expire_dcall')

        if not n.inlist:
            return

        # Remove from nodes list
        if self.syncd:
            del self.nodes[bisect.bisect_left(self.nodes, n)]
        else:
            self.nodes.remove(n)
        
        n.inlist = False

        # Tell the TopicManager this node is leaving
        self.tm.checkLeavingNode(n)

        # If it's a bridge node, clean up the extra data
        if n.bridge_data:
            n.bridge_data.nodeExited()
            n.bridge_data = None

        # Remove from the nick mapping
        self.nkm.removeNode(n, reason)
        n.nick = ''
        n.info = ''

        # Cancel any privmsg timeouts
        n.cancelPrivMsgs()

        # Remove from the SyncManager, if it's active
        if self.sm:
            self.sm.giveUpNode(n.ipp)

        # Remove from outbound links
        self.pgm.removeOutboundLink(n)

        # Maybe get more outbound links
        self.pgm.scheduleMakeNewLinks()

        
    def scheduleNodeExpire(self, n, when):
        # Schedule a timer for the given node to expire from the network

        print "scheduleNodeExpire: ipp=%s, when=%d" % (
            hexlify(n.ipp), when)
        
        if n.expire_dcall:
            n.expire_dcall.reset(when)
            return

        def cb(n):
            n.expire_dcall = None
            self.nodeExited(n, "Node Timeout")

        n.expire_dcall = reactor.callLater(when, cb, n)


    def getStatus(self):

        status = []

        # Exact time left before my status expires.
        # (The receiver will add a few buffer seconds.)
        status.append(struct.pack('!H', self.getMyExpireTime()))

        # My Session ID
        status.append(self.me.sesid)

        # My Uptime and Flags
        status.append(struct.pack('!I', int(seconds() - self.me.uptime)))
        status.append(self.me.flags())

        # My Nick
        status.append(struct.pack('!B', len(self.me.nick)))
        status.append(self.me.nick)

        # My Info
        status.append(struct.pack('!B', len(self.me.info)))
        status.append(self.me.info)

        return status


    def getMyExpireTime(self):
        # Find out how long we have before my own node expires
        return max(0, int(dcall_timeleft(self.sendStatus_dcall)))


    def updateMyInfo(self, send=False):
        # Grab my info from the DC client (if any) and maybe broadcast
        # it into the network.
        
        dch = self.main.getOnlineDCH()

        persist = self.main.state.persistent

        if dch:
            info = dch.formatMyInfo()
            nick = dch.nick
        else:
            info = ''
            nick = ''

        me = self.me
        send = send or (me.nick, me.info, me.persist) != (nick, info, persist)

        if me.nick != nick:
            if me.nick:
                self.nkm.removeNode(me)

            me.nick = nick
            me.info = info

            if me.nick:
                if not self.nkm.addNode(me):
                    me.nick = me.info = ''
                    dch.nickCollision()

        else:
            self.nkm.setNodeInfo(me, info)

        me.persist = persist

        if send and self.syncd:
            self.sendMyStatus()


    def sendMyStatus(self, sendfull=True):
        # Immediately send my status, and keep sending updates over time.

        if self.bsm:
            # Skip this stuff for Bridge Servers.
            # TODO: This is kinda ugly.  Would it make any sense to reorganize
            #       stuff into a Base class, with client and server subclasses?
            return

        def cb(sendfull):
            print "sending status..."

            # Choose an expiration time so that the network handles
            # approximately 1 status update per second, but set bounds of
            # about 1-15 minutes
            
            expire = max(60.0, min(900.0, len(self.nodes)))
            expire *= random.uniform(0.9, 1.1)

            self.sendStatus_dcall = reactor.callLater(expire, cb, False)

            pkt_id = struct.pack('!I', self.mrm.getPacketNumber_status())

            if sendfull:
                packet = self.mrm.broadcastHeader('NS', self.me.ipp)
                packet.append(pkt_id)
                packet.extend(self.getStatus())

            else:
                infohash = self.me.infoHash()

                packet = self.mrm.broadcastHeader('NH', self.me.ipp)
                packet.append(pkt_id)

                packet.append(struct.pack('!H', expire))
                packet.append(infohash)

            self.mrm.newMessage(''.join(packet), mystatus=True)

        dcall_discard(self, 'sendStatus_dcall')
        cb(sendfull)


    def sendLoginEcho(self):
        # Send a packet to myself, in order to determine how my router
        # (if any) reacts to loopback'd packets.
        
        def cb():
            self.loginEcho_dcall = None
            self.loginEcho_rand = None
            print "loginEcho: Did not get reply"

        echorand = ''.join([chr(random.randint(0,255)) for i in range(8)])

        packet = ['EC']
        packet.append(echorand)

        ad = Ad().setRawIPPort(self.me.ipp)
        self.main.ph.sendPacket(''.join(packet), ad.getAddrTuple())

        self.loginEcho_dcall = reactor.callLater(3.0, cb)
        self.loginEcho_rand = echorand


    def receivedLoginEcho(self, ad, rand):
        if rand != self.loginEcho_rand:
            print "loginEcho: rand mismatch"
            return

        myad = Ad().setRawIPPort(self.me.ipp)

        dcall_discard(self, 'loginEcho_dcall')
        self.loginEcho_rand = None

        if ad.ip == myad.ip:
            print "loginEcho: remapping not needed"
            return

        if ad.isRFC1918():
            # This matches an RFC1918 address, so it looks like a router.
            # Remap this address to my external IP in the future

            self.main.ph.remap_ip = (ad.ip, myad.ip)
            print "loginEcho: remapping %s->%s" % (ad.ip, myad.ip)

        else:
            print "loginEcho: Not RFC1918 address."


    def makeExitPacket(self):
        packet = self.mrm.broadcastHeader('NX', self.me.ipp)
        packet.append(self.me.sesid)
        return ''.join(packet)


    def shutdown(self):
        
        # Cancel all the dcalls here
        dcall_discard(self, 'sendStatus_dcall')

        # TODO: remove debugging dcall!
        dcall_discard(self, 'printNodes_dcall')

        # Tell the DC client that all nicks are gone
        if self.nkm:
            self.nkm.quitEverybody()

        # Reset the kick/collision state (if any)
        if self.main.dch:
            self.main.dch.dtellaShutdown()

        # If I'm still syncing, shutdown the SyncManager
        if self.sm:
            self.sm.shutdown()

        # Shut down the MessageRoutingManager (and broadcast NX)
        if self.mrm:
            self.mrm.shutdown()

        # Shut down the BridgeServerManager
        if self.bsm:
            self.bsm.shutdown()

        # Shut down all nodes
        for n in self.nodes:
            n.shutdown()

        # Shut down the PingManager (and notify outbounds)
        if self.pgm:
            self.pgm.shutdown()

        # Shut down the SyncRequestRoutingManager
        if self.yqrm:
            self.yqrm.shutdown()

        # Shut down the ChatMessageSequencer
        if self.cms:
            self.cms.shutdown()


##############################################################################


class PingManager(object):

    OUTLINK_GOAL = 3

    def __init__(self, main):
        self.main = main

        self.chopExcessLinks_dcall = None
        self.makeNewLinks_dcall = None
        self.outbound = set()
        self.inbound = set()

        self.onlineTimeout_dcall = None
        self.scheduleOnlineTimeout()


    def receivedPing(self, src_ipp, uwant, u_got_ack, req_key, ack_key, nbs):

        osm = self.main.osm

        try:
            n = osm.lookup_ipp[src_ipp]
        except KeyError:
            if not osm.syncd:
                raise BadTimingError("Not ready to accept pings yet")
            n = osm.lookup_ipp[src_ipp] = Node(src_ipp)

        iwant = (n in self.outbound)

        # If we're not fully online yet, then reject pings that we never
        # asked for.

        if not (osm.syncd or iwant):
            return

        # Save list of neighbors
        if nbs is not None:
            n.ping_nbs = tuple(nbs)

        # Put n in inbound iff we got a uwant
        if uwant:
            self.inbound.add(n)
        else:
            self.inbound.discard(n)

        # If they requested an ACK, then we'll want to ping soon
        ping_now = bool(req_key)

        was_stronglyConnected = n.stronglyConnected()

        # Keep track of whether the remote node has received an ack from us
        n.u_got_ack = u_got_ack

        # If this ping contains an acknowledgement...
        if ack_key:
            try:
                sendtime = n.reqs[ack_key]
            except KeyError:
                # TODO: maybe give /some/ credit to older pings?
                print "Unknown ping ack"
            else:
                print "Ping delay: %f ms" % ((seconds() - sendtime) * 1000.0)

                # If we just got the first ack, then send a ping now to
                # send the GOTACK bit to neighbor
                if not n.got_ack:
                    n.got_ack = True
                    ping_now = True

                dcall_discard(n, 'nodeFail_dcall')

                # Schedule next ping in ~5 seconds
                self.pingWithRetransmit(n, tries=4, later=True)

                # Got ack, so reset the online timeout
                self.scheduleOnlineTimeout()

        if not was_stronglyConnected and n.stronglyConnected():

            # Just got strongly connected.
            if n in self.outbound:
                self.scheduleChopExcessLinks()

            # If we have a good solid link, then the sync procedure
            # can begin.
            if not (osm.syncd or osm.sm):
                osm.sm = SyncManager(self.main)

        # Decide whether to request an ACK.  This is in a nested
        # function to make the logic more redable.
        def i_req():
            if not (iwant or uwant):
                # Don't request an ack for an unwanted connection
                return False

            if not n.stillAlive():
                # Try to revitalize this connection
                return True

            if (ping_now and
                hasattr(n.sendPing_dcall, 'ping_is_shortable') and
                dcall_timeleft(n.sendPing_dcall) <= 1.0
                ):
                # We've got a REQ to send out in a very short time, so
                # send it out early with this packet we're sending already.
                return True
                
            return False
        
        if i_req():
            # Send a ping with ACK requesting + retransmits
            self.pingWithRetransmit(n, tries=4, later=False, ack_key=req_key)

        elif ping_now:
            # Send a ping without an ACK request
            self.sendPing(n, i_req=False, ack_key=req_key)

        # If neither end wants this connection, throw it away.
        if not (iwant or uwant):
            self.cancelInactiveLink(n)


    def pingWithRetransmit(self, n, tries, later, ack_key=None):

        dcall_discard(n, 'sendPing_dcall')
        n.reqs.clear()

        def cb(n, tries):
            n.sendPing_dcall = None

            # Send the ping
            self.sendPing(n, True)

            # While tries is positive, use 1 second intervals.
            # When it hits zero, trigger a timeout.  As it goes negative,
            # pings get progressively more spaced out.

            if tries > 0:
                when = 1.0
            else:
                when = 2.0 ** min(-tries, 7)  # max of 128 sec

            # Tweak the delay
            when *= random.uniform(0.9, 1.1)

            # Schedule retransmit
            n.sendPing_dcall = reactor.callLater(when, cb, n, tries-1)

            # Just failed now
            if tries == 0:

                if (self.main.osm.syncd and n.got_ack):
                    # Note that we had to set sendPing_dcall before this.
                    self.handleNodeFailure(n)

                n.got_ack = False

                # If this was an inbound node, forget it.
                self.inbound.discard(n)

                if n in self.outbound:
                    # An outbound link just failed.  Go find another one.
                    self.scheduleMakeNewLinks()
                else:
                    # Neither side wants this link.  Clean up.
                    self.cancelInactiveLink(n)


        if later:
            when = 5.0
        else:
            # Send first ping
            self.sendPing(n, True, ack_key)
            tries -= 1
            when = 1.0

        # Schedule retransmit(s)
        when *= random.uniform(0.9, 1.1)
        n.sendPing_dcall = reactor.callLater(when, cb, n, tries)

        # Leave a flag value in the dcall so we can test whether this
        # ping can be made a bit sooner
        if later:
            n.sendPing_dcall.ping_is_shortable = True


    def cancelInactiveLink(self, n):
        n.got_ack = False
        n.u_got_ack = False
        n.ping_nbs = None
        n.reqs.clear()
        dcall_discard(n, 'sendPing_dcall')
        dcall_discard(n, 'nodeFail_dcall')


    def handleNodeFailure(self, n, nb_ipp=None):

        osm = self.main.osm

        # A bridge node will just have to time out on its own
        if n.bridge_data:
            return

        # If this node isn't my neighbor, then don't even bother.
        if not n.sendPing_dcall:
            return

        # Only accept a remote failure if that node is a neighbor of n.
        if nb_ipp and n.ping_nbs is not None and nb_ipp not in n.ping_nbs:
            return

        # If the node's about to expire anyway, don't bother
        if not (n.expire_dcall and
                dcall_timeleft(n.expire_dcall) > NODE_EXPIRE_EXTEND * 1.1):
            return

        failedMe = not n.stillAlive()

        # Trigger an NF message if I've experienced a failure, and:
        # - someone else just experienced a failure, or
        # - someone else experienced a failure recently, or
        # - I seem to be n's only neighbor.

        pkt_id = struct.pack('!I', n.status_pktnum)

        if failedMe and (nb_ipp or n.nodeFail_dcall or n.ping_nbs==()):

            dcall_discard(n, 'nodeFail_dcall')

            packet = osm.mrm.broadcastHeader('NF', n.ipp)
            packet.append(pkt_id)
            packet.append(n.sesid)

            osm.mrm.newMessage(''.join(packet))

            osm.scheduleNodeExpire(n, NODE_EXPIRE_EXTEND)

        elif nb_ipp:
            # If this failure was reported by someone else, then set the
            # nodeFail_dcall, so when I detect a failure, I'll be sure of it.

            def cb():
                n.nodeFail_dcall = None

            dcall_discard(n, 'nodeFail_dcall')
            n.nodeFail_dcall = reactor.callLater(15.0, cb)

        elif n.ping_nbs:
            # Reported by me, and n has neighbors, so
            # Send Possible Failure message to n's neighbors

            packet = ['PF']
            packet.append(osm.me.ipp)
            packet.append(n.ipp)
            packet.append(pkt_id)
            packet.append(n.sesid)
            packet = ''.join(packet)

            for nb_ipp in n.ping_nbs:
                ad = Ad().setRawIPPort(nb_ipp)
                self.main.ph.sendPacket(packet, ad.getAddrTuple())


    def scheduleMakeNewLinks(self):
        # Call this whenever a new sync'd node is added
        # Or when a connected link dies

        # This never needs to run more than once per reactor loop
        if self.makeNewLinks_dcall:
            return

        def cb():
            self.makeNewLinks_dcall = None

            osm = self.main.osm

            # Make sure the K closest nonbroken nodes are marked as outbound
            n_alive = 0
            for n in osm.nodes:
                
                if n not in self.outbound:

                    if n not in self.inbound:
                        # Completely new link
                        tries = 2

                    elif n.stronglyConnected():
                        # An active inbound link is being marked as outbound,
                        # so we might want to close some other outbound
                        # link.  Note that this won't run until the next
                        # reactor loop.
                        self.scheduleChopExcessLinks()
                        tries = 4

                    else:
                        # Existing link, not strongly connected yet
                        tries = 2

                    self.outbound.add(n)
                    self.pingWithRetransmit(n, tries=tries, later=False)

                if n in self.outbound and n.stillAlive():
                    n_alive += 1
                    if n_alive >= self.OUTLINK_GOAL:
                        break

        self.makeNewLinks_dcall = reactor.callLater(0, cb)


    def scheduleChopExcessLinks(self):
        # Call this whenever a link goes from a connecting state to an
        # active state.
        
        # This never needs to run more than once per reactor loop
        if self.chopExcessLinks_dcall:
            return

        def cb():
            self.chopExcessLinks_dcall = None

            osm = self.main.osm

            # Remove any unnecessary nodes.

            n_alive = 0

            for i,n in enumerate(osm.nodes):
                
                if n not in self.outbound:
                    # We ran out of nodes before hitting the target number
                    # of strongly connected nodes.  That means stuff's still
                    # connecting, and there's no need to remove anyone.
                    break

                if n.stronglyConnected():
                    n_alive += 1
                    if n_alive == self.OUTLINK_GOAL:

                        # Chop off the excess outbound links
                        excess = self.outbound.difference(osm.nodes[:i+1])
                        
                        for n in excess:
                            self.removeOutboundLink(n)

                        break

        self.chopExcessLinks_dcall = reactor.callLater(0, cb)


    def scheduleOnlineTimeout(self):
        # This will automatically shut down the node if we don't get any
        # ping acknowledgements for a while

        if self.onlineTimeout_dcall:
            self.onlineTimeout_dcall.reset(ONLINE_TIMEOUT)
            return

        def cb():
            self.onlineTimeout_dcall = None
            self.main.showLoginStatus("Lost Sync!")
            self.main.shutdown()

        self.onlineTimeout_dcall = reactor.callLater(ONLINE_TIMEOUT, cb)


    def removeOutboundLink(self, n):
        try:
            self.outbound.remove(n)
        except KeyError:
            return
        
        # Send iwant=0 to neighbor
        if n in self.inbound:
            self.pingWithRetransmit(n, tries=4, later=False)
        else:
            self.sendPing(n, i_req=False, ack_key=None)
            self.cancelInactiveLink(n)


    def sendPing(self, n, i_req, ack_key=None):
        # Transmit a single ping to the given node

        osm = self.main.osm

        # Expire old ack requests
        if n.reqs:
            now = seconds()
            for req_key, when in n.reqs.items():
                if now - when > 15.0:
                    del n.reqs[req_key]

        iwant = (n in self.outbound)

        # For now, include neighbor list only when requesting an ack.
        nblist = i_req

        # Build packet
        packet = ['PG']
        packet.append(osm.me.ipp)

        flags = ((iwant and IWANT_BIT)       |
                 (n.got_ack and GOTACK_BIT)  |
                 (i_req and REQ_BIT)         |
                 (bool(ack_key) and ACK_BIT) |
                 (nblist and NBLIST_BIT)
                 )
        
        packet.append(struct.pack('!B', flags))

        if i_req:
            # I'm requesting that this packet be acknowledged, so generate
            # a new req_key
            while True:
                req_key = randbytes(4)
                if req_key not in n.reqs:
                    break

            n.reqs[req_key] = seconds()
            packet.append(req_key)

        if ack_key:
            packet.append(ack_key)

        if nblist:
            if osm.syncd:
                # Grab my list of ping neighbors.
                nbs = [nb.ipp for nb in self.inbound | self.outbound
                       if (nb.ipp != n.ipp and
                           nb.expire_dcall and
                           nb.stronglyConnected())
                       ]

                # Don't bother sending more than 8
                nbs.sort()
                del nbs[8:]
            else:
                nbs = []

            packet.append(struct.pack("!B", len(nbs)))
            packet.extend(nbs)

        ad = Ad().setRawIPPort(n.ipp)
        self.main.ph.sendPacket(''.join(packet), ad.getAddrTuple())


    def shutdown(self):
        dcall_discard(self, 'chopExcessLinks_dcall')
        dcall_discard(self, 'makeNewLinks_dcall')
        dcall_discard(self, 'onlineTimeout_dcall')

        ob = tuple(self.outbound)

        for n in self.outbound | self.inbound:
            self.cancelInactiveLink(n)

        self.inbound.clear()
        self.outbound.clear()

        for n in ob:
            self.sendPing(n, i_req=False, ack_key=None)


##############################################################################


class MessageRoutingManager(object):

    class Message(object):

        def __init__(self, data, tries):
            self.data = data
            self.expire_dcall = None
            self.tries = tries

            self.status_pktnum = None

            # {neighbor ipp -> ack-timeout dcall}
            self.nbs = {}


        def scheduleExpire(self, msgs, ack_key):
            if self.expire_dcall:
                self.expire_dcall.reset(60.0)
                return

            def cb(msgs, ack_key):
                self.shutdown()
                del msgs[ack_key]

            self.expire_dcall = reactor.callLater(60.0, cb, msgs, ack_key)


        def sendToNeighbor(self, nb_ipp, ph):
            # If we don't need to transmit this message, 
            
            if nb_ipp in self.nbs:
                # This neighbor has already seen our message
                return

            def cb(data, tries):
                # Ack timeout callback

                # The number of tries may be reduced externally
                tries = min(tries, self.tries)

                # Make an attempt now
                if tries > 0:
                    addr = Ad().setRawIPPort(nb_ipp).getAddrTuple()
                    ph.sendPacket(data, addr)

                # Reschedule another attempt
                if tries-1 > 0:
                    when = random.uniform(1.0, 2.0)
                    self.nbs[nb_ipp] = reactor.callLater(
                        when, cb, data, tries-1)
                else:
                    self.nbs[nb_ipp] = None

            cb(self.data, self.tries)


        def shutdown(self):
            # Cancel any pending retransmits
            
            for d in self.nbs.itervalues():
                if d:
                    d.cancel()

            self.nbs.clear()


    def __init__(self, main):
        self.main = main
        self.send_dcall = None
        self.outbox = []
        self.msgs = {}

        self.mystatus_msg = None

        r = random.randint(0, 0xFFFFFFFF)
        self.search_pktnum = r
        self.chat_pktnum = r
        self.main.osm.me.status_pktnum = r


    def scheduleSendMessages(self):
        if self.send_dcall:
            return

        def cb():
            self.send_dcall = None
            
            osm = self.main.osm

            # Get my current neighbors who we know to be alive.  We don't
            # need to verify n.u_got_ack because it doesn't really matter
            # if they filter our traffic.
            sendto = [n for n in osm.pgm.inbound | osm.pgm.outbound
                      if n.got_ack]

            # For each message waiting to be sent, send to each of my
            # neighbors who needs it
            for m in self.outbox:
                for n in sendto:
                    m.sendToNeighbor(n.ipp, self.main.ph)

            # Clear the outbox
            del self.outbox[:]

        self.send_dcall = reactor.callLater(0, cb)


    def generateKey(self, data):
        # 0:2 = kind
        # 2:8 = neighbor ipp
        # 8:9 = hop limit
        # 9:10 = flags
        # 10:16 = source ipp
        # 16: = "the rest"
        return md5.new(data[0:2] + data[10:]).digest()[:8]


    def pokeMessage(self, ack_key, nb_ipp):
        # If we know about this message, then mark down that this neighbor
        # has acknowledged it.

        try:
            m = self.msgs[ack_key]
        except KeyError:
            # Don't know about this message
            return False

        # Extend the expiration time.
        m.scheduleExpire(self.msgs, ack_key)

        # Is this locally generated?
        if not nb_ipp:
            return True

        # If we just received an ack for one of my status messages, then
        # Reduce the number of retries for the other neighbors.
        if m is self.mystatus_msg:
            m.tries = min(m.tries, 1)

        # Tell the message that this neighbor acknowledged it.
        try:
            m.nbs[nb_ipp].cancel()
        except (KeyError, AttributeError):
            pass
        m.nbs[nb_ipp] = None
        
        return True


    def newMessage(self, data, nb_ipp=None, tries=2, mystatus=False):
        # Forward a new message to my neighbors

        ack_key = self.generateKey(data)

        if ack_key in self.msgs:
            print "Tried to create a duplicate message"
            return

        m = self.msgs[ack_key] = self.Message(data, tries)
        self.pokeMessage(ack_key, nb_ipp)

        osm = self.main.osm

        # Try extra hard to make sure my own status messages get delivered.
        if mystatus:
            # Use an absurd number of retries for now.
            # This number will be reduced if another node acks the message,
            # or if I replace it with another status message.
            tries = 100
            
            # Cancel retry attempts for the previous status message
            if self.mystatus_msg:
                self.mystatus_msg.tries = 0

        if data[10:16] == osm.me.ipp and data[0:2] in ('NH','CH','SQ'):
            # Save the current status_pktnum for this message, because it's
            # useful if we receive a Reject message later.
            m.status_pktnum = osm.me.status_pktnum

        if tries > 0:
            # Put message into the outbox
            self.outbox.append(m)
            self.scheduleSendMessages()


    def receivedRejection(self, ack_key):
        # Broadcast rejection, sent in response to a previous broadcast if
        # another node doesn't recognize us on the network.

        # We attach a status_pktnum to any broadcast which could possibly
        # be rejected.  If this matches my status_pktnum now, then we should
        # broadcast a new status, which will change status_pktnum and
        # prevent this same broadcast from triggering another status update.

        osm = self.main.osm

        try:
            m = self.msgs[ack_key]
        except KeyError:
            raise BadTimingError("Reject refers to an unknown broadcast")

        if m.status_pktnum is None:
            raise BadTimingError("Reject refers to a nonrejectable broadcast")
        
        if osm.me.status_pktnum != m.status_pktnum:
            raise BadTimingError("Reject matches an outdated status_pktnum.")

        # Looks ok, so rebroadcast my status
        osm.sendMyStatus()


    def getPacketNumber_search(self):
        self.search_pktnum = (self.search_pktnum + 1) % 0x100000000
        return self.search_pktnum


    def getPacketNumber_chat(self):
        self.chat_pktnum = (self.chat_pktnum + 1) % 0x100000000
        return self.chat_pktnum


    def getPacketNumber_status(self):
        me = self.main.osm.me
        me.status_pktnum = (me.status_pktnum + 1) % 0x100000000
        return me.status_pktnum


    def broadcastHeader(self, kind, src_ipp, hops=64, flags=0):
        # Build the header used for all broadcast packets
        packet = [kind]
        packet.append(self.main.osm.me.ipp)
        packet.append(struct.pack('!BB', hops, flags))
        packet.append(src_ipp)
        return packet


    def shutdown(self):
        # Cancel everything

        dcall_discard(self, 'send_dcall')

        for m in self.msgs.values():
            dcall_discard(m, 'expire_dcall')
            m.shutdown()

        # Immediately broadcast NX to my neighbors

        ph = self.main.ph
        osm = self.main.osm

        if (osm and osm.syncd):
            sendto = [n for n in osm.pgm.inbound | osm.pgm.outbound]

            packet = osm.makeExitPacket()

            for n in sendto:
                ad = Ad().setRawIPPort(n.ipp)
                ph.sendPacket(packet, ad.getAddrTuple())


##############################################################################


class SyncRequestRoutingManager(object):
    
    class Message(object):
        
        def __init__(self, msgs, key):
            self.nbs = {}   # {ipp: max hop count}
            self.expire_dcall = None


        def scheduleExpire(self, msgs, key):
            if self.expire_dcall:
                self.expire_dcall.reset(180.0)
                return

            def cb(msgs, key):
                del msgs[key]
            
            self.expire_dcall = reactor.callLater(180.0, cb, msgs, key)
            

    def __init__(self, main):
        self.main = main
        self.msgs = {}


    def receivedSyncRequest(self, nb_ipp, src_ipp, sesid, hop, timedout):
        
        osm = self.main.osm
        ph  = self.main.ph

        key = (src_ipp, sesid)

        # Get all syncd neighbors who we've heard from recently
        nbs = [n for n in osm.pgm.inbound | osm.pgm.outbound
               if n.expire_dcall and n.got_ack]

        # Put neighbors in random order
        random.shuffle(nbs)

        # See if we've seen this sync message before
        try:
            m = self.msgs[key]
            isnew = False
        except KeyError:
            m = self.msgs[key] = self.Message(self.msgs, key)
            isnew = True

        # Expire the message in a while
        m.scheduleExpire(self.msgs, key)

        # Set the hop value of the neighbor who sent us this packet
        try:
            if m.nbs[nb_ipp] < hop+1:
                raise KeyError
        except KeyError:
            m.nbs[nb_ipp] = hop+1

        if hop > 0:
            # Build packet to forward
            packet = osm.mrm.broadcastHeader('YQ', src_ipp, hop-1)
            packet.append(sesid)
            packet = ''.join(packet)
            
            # Contacted/Uncontacted lists
            cont = []
            uncont = []

            for n in nbs:
                try:
                    if len(cont) >= 3 or m.nbs[n.ipp] >= hop-1:
                        uncont.append(n.ipp)
                        continue
                except KeyError:
                    pass

                cont.append(n.ipp)
                m.nbs[n.ipp] = hop-1

                ad = Ad().setRawIPPort(n.ipp)
                ph.sendPacket(packet, ad.getAddrTuple())

        else:
            # no hops left
            cont = []
            uncont = [n.ipp for n in nbs]

        # Cut off after 16 nodes, just in case
        uncont = uncont[:16]

        if isnew or timedout:
            self.sendSyncReply(src_ipp, cont, uncont)


    def sendSyncReply(self, src_ipp, cont, uncont):
        ad = Ad().setRawIPPort(src_ipp)
        osm = self.main.osm

        # Build Packet
        packet = ['YR']

        # My IP:Port
        packet.append(osm.me.ipp)

        # My last pktnum
        packet.append(struct.pack('!I', osm.me.status_pktnum))

        # Expire Time, Session ID, Uptime, Flags, Nick, Info
        packet.extend(osm.getStatus())

        # Contacted Nodes
        packet.append(struct.pack('!B', len(cont)))
        packet.extend(cont)

        # Uncontacted Nodes
        packet.append(struct.pack('!B', len(uncont)))
        packet.extend(uncont)

        self.main.ph.sendPacket(''.join(packet), ad.getAddrTuple())


    def shutdown(self):
        # Cancel all timeouts

        for m in self.msgs.values():
            dcall_discard(m, 'expire_dcall')


##############################################################################
        

class ChatMessageSequencer(object):
    # This whole class is a bit sloppy, but the purpose is to delay out-of-order
    # chat messages for a couple seconds if a message was skipped.
    
    class ChatInfo(object):
        def __init__(self, pointer):
            self.heap = []   # pktnum, nick, text
            self.pointer = pointer
            self.dcalls = {}

    def __init__(self, main):
        self.main = main
        self.info = {}


    def addMessage(self, ipp, pktnum, nick, text, flags):
        
        so = self.main.getStateObserver()
        if not so:
            return
        
        try:
            c = self.info[ipp]
        except KeyError:
            c = self.info[ipp] = self.ChatInfo(pktnum)

        # If the pointer is exactly where it needs to be, send and advance.
        if c.pointer == pktnum:
            so.event_ChatMessage(nick, text, flags)
            self.advancePointer(ipp, c.pointer+1)

        # If the packet number changes drastically, then just flush the
        # queue and start over.  This is also a sloppy way of handling the
        # 2^32 .. 0 wraparound.
        elif abs(c.pointer - pktnum) > PKTNUM_BUF:
            self.flushNode(ipp)
            c.pointer = pktnum + 1
            so.event_ChatMessage(nick, text, flags)

        # If the packet is lagged behind the current pointer, just send it
        # out of sequence.
        elif pktnum < c.pointer:
            so.event_ChatMessage(nick, text, flags)

        # The packet is ahead of the pointer, so send up to that point
        # in a couple seconds
        else:
            heapq.heappush(c.heap, (pktnum, nick, text, flags))
            if pktnum not in c.dcalls:
                
                def cb(c, ipp, pktnum):
                    del c.dcalls[pktnum]
                    self.advancePointer(ipp, pktnum)

                c.dcalls[pktnum] = reactor.callLater(2.0, cb, c, ipp, pktnum)


    def advancePointer(self, ipp, pointer):
        # Send all queued messages with a pktnum <= the pointer value

        try:
            c = self.info[ipp]
        except KeyError:
            return

        c.pointer = max(c.pointer, pointer)

        so = self.main.getStateObserver()

        while c.heap:
            pktnum, nick, text, flags = c.heap[0]
            
            if pktnum <= c.pointer:
                # Pointer is ahead of, or at, this message.  Send it.
                heapq.heappop(c.heap)
                if so:
                    so.event_ChatMessage(nick, text, flags)

                # If the packet number exactly matches, then advance
                if pktnum == c.pointer:
                    c.pointer += 1
            else:
                break


    def flushNode(self, ipp, kill=False):
        # Send all the packets in this node's chat queue, in order,
        # then wipe the queue and cancel all callbacks.
        try:
            c = self.info[ipp]
        except KeyError:
            return

        if kill:
            del self.info[ipp]

        for d in c.dcalls.values():
            d.cancel()
        
        c.dcalls.clear()

        so = self.main.getStateObserver()
        
        while c.heap:
            pktnum, nick, text, flags = heapq.heappop(c.heap)

            if so:
                so.event_ChatMessage(nick, text, flags)


    def shutdown(self):
        # Cancel all timeouts

        for c in self.info.values():
            for d in c.dcalls.values():
                d.cancel()


##############################################################################


class PrivateMessageManager(object):
    # Handles incoming private messages and connection requests

    def __init__(self, main):
        self.main = main


    def receivedMessage(self, kind, src_ipp, ack_key,
                        src_nhash, dst_nhash, *args):

        osm = self.main.osm

        ack_flags = 0

        try:
            # Make sure we're ready to receive it
            if not self.main.getOnlineDCH():
                raise Reject

            try:
                n = osm.lookup_ipp[src_ipp]
            except KeyError:
                # Never heard of this node
                raise Reject

            if not n.expire_dcall:
                # Node isn't online
                raise Reject
            
            if src_nhash != n.nickHash():
                # Source nickhash mismatch
                raise Reject
            
            if dst_nhash != osm.me.nickHash():
                # Dest nickhash mismatch
                raise Reject

            if n.pokePMKey(ack_key):
                # Haven't seen this message before, so handle it
                f = getattr(self, 'handleMessage_%s' % kind)
                f(n, *args)

        except Reject:
            ack_flags |= ACK_REJECT_BIT

        self.main.ph.sendAckPacket(src_ipp, ACK_PRIVATE, ack_flags, ack_key)


    def handleMessage_PM(self, n, notice, text):
        # Send private message to the DC client
        
        dch = self.main.getOnlineDCH()

        if notice:
            nick = "*N %s" % n.nick
            dch.pushChatMessage(nick, text)
        else:
            dch.pushPrivMsg(n.nick, text)


    def handleMessage_CA(self, n, port):
        # Send a $ConnectToMe to the DC client
        
        dch = self.main.getOnlineDCH()

        if port == 0:
            raise Reject

        ad = Ad().setRawIPPort(n.ipp)
        ad.port = port
        
        dch.pushConnectToMe(ad)
    

    def handleMessage_CP(self, n):
        # Send a $RevConnectToMe to the DC client
        
        dch = self.main.getOnlineDCH()

        dch.pushRevConnectToMe(n.nick)


##############################################################################


class TopicManager(object):

    def __init__(self, main):
        self.main = main
        self.topic = ""
        self.topic_node = None
        self.waiting = True


    def gotTopic(self, n, topic):
        self.updateTopic(n, n.nick, topic)


    def gotSyncTopic(self, src_ipp, ack_key, topic):

        osm = self.main.osm

        ack_flags = 0

        try:
            try:
                n = osm.lookup_ipp[src_ipp]
            except KeyError:
                # Never heard of this node
                raise Reject

            if not n.expire_dcall:
                # Node isn't online
                raise Reject

            if n.pokePMKey(ack_key):
                # Haven't seen this message before, so handle it

                if self.waiting:
                    self.updateTopic(n, None, topic)

        except Reject:
            ack_flags |= ACK_REJECT_BIT

        self.main.ph.sendAckPacket(src_ipp, ACK_PRIVATE,
                                   ack_flags, ack_key)


    def updateTopic(self, n, nick, topic, outdated=False):

        # Don't want any more SyncTopics
        self.waiting = False

        dch = self.main.getOnlineDCH()

        # Don't allow a non-bridge node to override a bridge's topic
        if self.topic_node and n:
            if self.topic_node.bridge_data and (not n.bridge_data):
                return False

        # Update stored topic, and title bar
        if (topic != self.topic) and (not outdated):
            self.topic = topic
            self.topic_node = n
            if dch:
                dch.pushTopic(topic)

        # Display the event as text (even if it's outdated)
        if dch and nick:
            dch.pushChatMessage(
                dch.bot.nick,
                "%s changed the topic to \"%s\"" % (nick, topic))

        return True


    def broadcastNewTopic(self, topic):
        osm = self.main.osm

        if len(topic) > 255:
            topic = topic[:255]

        # Update topic locally
        if not self.updateTopic(osm.me, osm.me.nick, topic):
            
            # Topic is controlled by a bridge node
            self.topic_node.bridge_data.sendTopicChange(topic)
            return

        packet = osm.mrm.broadcastHeader('TP', osm.me.ipp)
        packet.append(struct.pack('!I', osm.mrm.getPacketNumber_search()))

        packet.append(osm.me.nickHash())
        packet.append(struct.pack('!B', len(topic)))
        packet.append(topic)

        osm.mrm.newMessage(''.join(packet), tries=4)


    def checkNewNode(self, n):
        osm = self.main.osm
        
        # Check if I'm in charge of the topic
        if self.topic_node is not osm.me:
            print "Topic's not mine"
            return

        # If no topic is set, then don't bother.
        if not self.topic:
            print "Topic's empty"
            return

        ack_key = n.getPMAckKey()

        # Send a Topic Sync message to the new node
        packet = ['YT']
        packet.append(osm.me.ipp)
        packet.append(ack_key)
        packet.append(struct.pack('!B', len(self.topic)))
        packet.append(self.topic)
        packet = ''.join(packet)

        def fail_cb():
            print "YT failed"

        ph = self.main.ph
        n.sendPrivateMessage(ph, ack_key, packet, fail_cb)


    def checkLeavingNode(self, n):
        # If the node who set the topic leaves, wipe out the topic
        if self.topic_node is n:
            self.updateTopic(None, None, "")


##############################################################################            

        
class DtellaMain(object):
    def __init__(self):
       
        self.myip_reports = []

        self.blockers = set()

        self.reconnect_dcall = None
        self.disconnect_dcall = None

        self.reconnect_interval = RECONNECT_RANGE[0]

        # Initial Connection Manager
        self.icm = None

        # Neighbor Connection Manager
        self.osm = None

        # Login counter (just for eye candy)
        self.login_counter = 0
        self.login_text = ""

        # DC Handler(s)
        self.dch = None
        self.pending_dch = None

        # Location map: ipp->string, usually only contains 1 entry
        self.location = {}

        # State Manager
        self.state = dtella_state.StateManager(self, 'dtella.state')

        # Pakcet Encoder
        self.pk_enc = dtella_crypto.PacketEncoder(dtella_local.network_key)

        # DNS Handler
        self.dnsh = dtella_dnslookup.DNSHandler(self)

        # Peer Handler
        if dtella_bridgeclient:
            self.ph = dtella_bridgeclient.BridgeClientProtocol(self)
        else:
            self.ph = PeerHandler(self)

        self.bindUDPPort()

        # Register a function that runs before shutting down
        reactor.addSystemEventTrigger('before', 'shutdown',
                                      self.cleanupOnExit)

        if self.state.persistent:
            self.newConnectionRequest()


    def cleanupOnExit(self):
        print "Reactor is shutting down.  Doing cleanup."
        if self.dch:
            self.dch.state = 'shutdown'
        self.shutdown(final=True)
        self.state.saveState()


    def changeUDPPort(self, udp_port):
        # Shut down the node, and start up with a different UDP port

        if 'udp_change' in self.blockers:
            return False

        self.addBlocker('udp_change')

        self.state.udp_port = udp_port
        self.state.saveState()

        def cb(result):
            self.bindUDPPort()
            self.removeBlocker('udp_change')

        if self.ph.transport:
            self.ph.transport.stopListening().addCallback(cb)
        else:
            reactor.callLater(0, cb, None)

        return True


    def bindUDPPort(self):
        try:
            reactor.listenUDP(self.state.udp_port, self.ph)
        except twisted.internet.error.BindError:
            # TODO: more informative

            self.showLoginStatus("*** FAILED TO BIND UDP PORT ***")

            text = (
                "Dtella was not able to listen on UDP port %d. One possible "
                "reason for this is that you've tried to make your DC "
                "client use the same UDP port as Dtella. Two programs "
                "are not allowed listen on the same port.  To tell Dtella "
                "to use a different port, type !UDP followed by a number. "
                "Note that if you have a firewall or router, you will have "
                "to tell it to let traffic through on this port."
                % self.state.udp_port
                )

            for line in word_wrap(text):
                self.showLoginStatus(line)
            
            if 'udp_bind' not in self.blockers:
                self.addBlocker('udp_bind')
        else:
            if 'udp_bind' in self.blockers:
                self.removeBlocker('udp_bind')


    def addBlocker(self, name):
        # Add a blocker.  Connecting will be prevented until the
        # blocker is removed.
        self.blockers.add(name)
        self.shutdown()


    def removeBlocker(self, name):
        # Remove a blocker, and start connecting if there are no more left.
        self.blockers.remove(name)
        self.startConnecting()


    def newConnectionRequest(self):
        # This fires when the DC client connects and wants to be online

        dcall_discard(self, 'disconnect_dcall')

        # Reset reconnect timer
        self.reconnect_interval = RECONNECT_RANGE[0]
        dcall_discard(self, 'reconnect_dcall')

        if self.icm or self.osm:
            # Already connecting, just wait.
            return

        # If an update is necessary, this will add a blocker
        self.dnsh.updateIfStale()

        # If we don't have the UDP port, then try again now.
        if 'udp_bind' in self.blockers:
            self.bindUDPPort()
            return

        # Start connecting now if there are no blockers
        
        self.startConnecting()


    def startConnecting(self):
        # If all the conditions are right, start connection procedure

        assert not (self.icm or self.osm)

        dcall_discard(self, 'reconnect_dcall')
        
        if self.blockers:
            return

        if not (self.dch or self.state.persistent):
            return

        def cb():
            icm = self.icm
            self.icm = None
            
            if icm.node_ipps:
                self.startNodeSync(icm.node_ipps)
            else:
                if not (icm.stats_bad_ip or icm.stats_dead_port):
                    self.showLoginStatus("No online nodes found.")
                    self.shutdown()

                elif icm.stats_bad_ip >= icm.stats_dead_port:
                    self.showLoginStatus("Your IP address is not authorized to use this network.")
                    self.shutdown(final=True)

                else:
                    self.reportDeadPort()
                    self.shutdown(final=True)

        self.ph.remap_ip = None
        self.icm = InitialContactManager(self, cb)


    def startNodeSync(self, node_ipps=()):
        # Determine my IP address and enable the osm

        assert not (self.icm or self.osm or self.blockers)
            
        # Reset the reconnect interval
        self.reconnect_interval = RECONNECT_RANGE[0]
        dcall_discard(self, 'reconnect_dcall')
        
        # Get my address and port
        try:
            my_ipp = self.selectMyIP()
        except ValueError:
            print "I don't know who I am!"
            return

        self.queryLocation(my_ipp)

        if dtella_bridgeclient:
            bcm = dtella_bridgeclient.BridgeClientManager(self)
        else:
            bcm = None

        # Enable the object that keeps us online
        self.osm = OnlineStateManager(self, my_ipp, node_ipps, bcm=bcm)


    def queryLocation(self, my_ipp):
        # Try to convert the IP address into a human-readable location name.
        # This might be slightly more complicated than it really needs to be.

        ad = Ad().setRawIPPort(my_ipp)
        my_ip = ad.getTextIP()

        skip = False
        for ip,loc in self.location.items():
            if ip == my_ip:
                skip = True
            elif loc:
                # Forget old entries
                del self.location[ip]

        # If we already had an entry for this IP, then don't start
        # another lookup.
        if skip:
            return

        # A location of None indicates that a lookup is in progress
        self.location[my_ip] = None

        def cb(hostname):
            
            # Use dtella_local to transform this hostname into a
            # human-readable location
            if hostname:
                loc = dtella_local.hostnameToLocation(hostname)
            else:
                loc = None

            # If we got a location, save it, otherwise dump the
            # dictionary entry
            if loc:
                self.location[my_ip] = loc
            else:
                del self.location[my_ip]

            # Maybe send an info update
            if self.osm:
                self.osm.updateMyInfo()

        # Start lookup
        self.dnsh.ipToHostname(ad, cb)


    def reportDeadPort(self):

        port = self.state.udp_port

        self.showLoginStatus("*** UDP PORT FORWARD REQUIRED ***")

        text = (
            "In order for Dtella to communicate properly, it needs to "
            "receive UDP traffic from the Internet.  Dtella is currently "
            "listening on UDP port %d, but the packets appear to be "
            "getting blocked, most likely by a firewall or a router. "
            "If this is the case, then you will have to configure your "
            "firewall or router to allow UDP traffic through on this port. "
            "You may tell Dtella to use a different port from now on by "
            "typing !UDP followed by a number." % self.state.udp_port
            )
        
        for line in word_wrap(text):
            self.showLoginStatus(line)


    def showLoginStatus(self, text, counter=None):

        # counter can be:
        # - int: set the counter to this value
        # - 'inc': increment from the previous counter value
        # - None: don't show a counter

        if type(counter) is int:
            self.login_counter = counter
        elif counter == 'inc':
            self.login_counter += 1

        if counter is not None:
            # Prepend a number
            text = "%d. %s" % (self.login_counter, text)

            # This text will be remembered for new DC clients
            self.login_text = text
        
        dch = self.dch
        if dch:
            dch.pushStatus(text)


    def shutdown(self, final=False):
        # Do a total shutdown of this Dtella node

        if self.icm or self.osm:
            self.showLoginStatus("Shutting down.")

        dcall_discard(self, 'reconnect_dcall')
        dcall_discard(self, 'disconnect_dcall')

        # Shut down InitialContactManager
        if self.icm:
            self.icm.shutdown()
            self.icm = None

        # Shut down OnlineStateManager
        if self.osm:
            self.osm.shutdown()
            self.osm = None

        # Schedule a Reconnect (maybe) ...
        
        if final:
            # Final shutdown, don't reconnect.
            return
        
        if self.blockers:
            # Reconnect will happen after the blockers are done
            return

        if not (self.dch or self.state.persistent):
            # No use for this connection; don't reconnect.
            return

        # Decide how long to wait before reconnecting
        when = self.reconnect_interval * random.uniform(0.8, 1.2)

        # Increase the reconnect interval logarithmically
        self.reconnect_interval = min(self.reconnect_interval * 1.5,
                                      RECONNECT_RANGE[1])

        self.showLoginStatus("Reconnecting in %d seconds." % when)

        def cb():
            self.reconnect_dcall = None
            self.startConnecting()
            
        self.reconnect_dcall = reactor.callLater(when, cb)


    def addDCHandler(self, dch):
        self.dch = dch

        oldtext = self.login_text
        self.login_text = ""

        self.newConnectionRequest()

        if self.osm and oldtext and not self.login_text:
            # The connection request didn't trigger any text, so show
            # the previous status to this new DC client.
            self.login_text = oldtext
            dch.pushStatus(oldtext)


    def removeDCHandler(self):
        # DC client has left.
        
        self.dch = None

        if self.osm:
            # Announce the DC client's departure
            self.osm.updateMyInfo()

            # Cancel all private message timeouts
            for n in self.osm.nodes:
                n.cancelPrivMsgs()

        # If another handler is waiting, let it on.
        if self.pending_dch:
            self.pending_dch.accept()
            return

        # Maybe skip the disconnect
        if self.state.persistent or not (self.icm or self.osm):
            return

        # Client left, so shut down in a while
        when = NO_CLIENT_TIMEOUT

        print "Shutting down in %d seconds." % when

        if self.disconnect_dcall:
            self.disconnect_dcall.reset(when)
            return

        def cb():
            self.disconnect_dcall = None
            self.shutdown()

        self.disconnect_dcall = reactor.callLater(when, cb)


    def getOnlineDCH(self):
        # Return DCH, iff it's fully online.

        if not (self.osm and self.osm.syncd):
            return None
        
        if self.dch and self.dch.state=='ready':
            return self.dch

        return None


    def getStateObserver(self):
        return self.getOnlineDCH()


    def addMyIPReport(self, from_ad, my_ad):
        # fromip = the IP who sent us this guess
        # myip = the IP that seems to belong to us

        if not (from_ad.validate() and my_ad.validate()):
            return

        fromip = from_ad.getRawIP()
        myip = my_ad.getRawIP()
        
        # If we already have a report from this fromip in the list, remove it.
        try:
            i = [r[0] for r in self.myip_reports].index(fromip)
            del self.myip_reports[i]
        except ValueError:
            pass

        # Only let list grow to 5 entries
        del self.myip_reports[:-4]

        # Append this guess to the end
        self.myip_reports.append((fromip, myip))


    def selectMyIP(self):
        # Out of the last 5 responses, pick the IP that occurs most often.
        # In case of a tie, pick the more recent one.  This whole IP detection
        # thing is mostly stupid, but it's better than just trusting a
        # single response.

        ips = [r[1] for r in self.myip_reports]
        ips.reverse()

        counts = {}

        for ip in ips:
            try:
                counts[ip] += 1
            except KeyError:
                counts[ip] = 1

        maxc = max(counts.values())

        for ip in ips:
            if counts[ip] == maxc:
                ad = Ad().setRawIP(ip)
                ad.port = self.state.udp_port
                return ad.getRawIPPort()

        raise ValueError


VERSION = "DEV"

if __name__=='__main__':
        
    dtMain = DtellaMain()

    #def kill():
    #    print "20-sec timeout"
    #    reactor.stop()
    #reactor.callLater(20.0, kill)
    #import profile
    #profile.run('reactor.run()')

    import dtella_dc
    dfactory = dtella_dc.DCFactory(dtMain)

    tcp_port = 7314
    reactor.listenTCP(tcp_port, dfactory, interface='127.0.0.1')

    print "Dtella Experimental %s" % VERSION
    print "Listening on 127.0.0.1:%d" % tcp_port
    reactor.run()
