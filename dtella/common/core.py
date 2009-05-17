"""
Dtella - Core P2P Module
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

import struct
import heapq
import time
import random
import bisect
import socket
from binascii import hexlify

from twisted.internet.protocol import DatagramProtocol
from twisted.internet import reactor, defer
from twisted.python.runtime import seconds
import twisted.internet.error

import dtella.local_config as local
import dtella.common.crypto
from dtella.common.util import (RandSet, dcall_discard, dcall_timeleft,
                                randbytes, validateNick, word_wrap, md5,
                                parse_incoming_info, get_version_string,
                                parse_dtella_tag, CHECK, SSLHACK_filter_flags)
from dtella.common.ipv4 import Ad, SubnetMatcher
from dtella.common.log import LOG

from zope.interface import implements
from zope.interface.verify import verifyClass
from dtella.common.interfaces import IDtellaNickNode

# Check for some non-fatal but noteworthy conditions.
def doWarnings():
    import twisted
    from twisted.python import versions
    if (twisted.version < versions.Version('twisted', 8, 0, 0)):
        LOG.warning("You should get Twisted 8 or later.  Previous versions "
                    "have some bugs that affect Dtella.")

    import Crypto.PublicKey
    try:
        import Crypto.PublicKey._fastmath
    except ImportError:
        LOG.warning("Your version of PyCrypto was compiled without "
                    "GMP (fastmath).  Some stuff will be slower.")
doWarnings()

# Miscellaneous Exceptions
class BadPacketError(Exception):
    pass

class BadTimingError(Exception):
    pass

class BadBroadcast(Exception):
    pass

class Reject(Exception):
    pass

class NickError(Exception):
    pass

class MessageCollisionError(Exception):
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
OFFLINE_BIT = 0x20

# Broadcast Flags
REJECT_BIT = 0x1

# Ack flags
ACK_REJECT_BIT = 0x1

# Sync Flags
TIMEDOUT_BIT = 0x1

# Chat Flags
SLASHME_BIT = 0x1
NOTICE_BIT = 0x2

# ConnectToMe Flags
USE_SSL_BIT = 0x1

# ACK Modes
ACK_PRIVATE = 1
ACK_BROADCAST = 2

# Bridge topic change
CHANGE_BIT = 0x1

# Bridge Kick flags
REJOIN_BIT = 0x1

# Bridge general flags
MODERATED_BIT = 0x1

# Init response codes
CODE_IP_OK = 0
CODE_IP_FOREIGN = 1
CODE_IP_BANNED = 2


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


    def removeNode(self, n, reason):
        try:
            if self.nickmap[n.nick.lower()] is not n:
                raise KeyError
        except KeyError:
            return

        del self.nickmap[n.nick.lower()]

        so = self.main.getStateObserver()
        if so:
            so.event_RemoveNick(n, reason)

        # Clean up nick-specific stuff
        if n.is_peer:
            n.nickRemoved(self.main)


    def addNode(self, n):

        if not n.nick:
            return

        lnick = n.nick.lower()

        if lnick in self.nickmap:
            raise NickError("collision")

        so = self.main.getStateObserver()
        if so:
            # Might raise NickError
            so.event_AddNick(n)
            so.event_UpdateInfo(n)

        self.nickmap[lnick] = n


    def setInfoInList(self, n, info):
        # Set the info of the node, and synchronize the info with
        # an observer if it changes.

        if not n.setInfo(info):
            # dcinfo hasn't changed, so there's nothing to send
            return

        # Look for this node in the nickmap
        try:
            if self.nickmap[n.nick.lower()] is not n:
                raise KeyError
        except KeyError:
            return

        # Push new dcinfo to dch/ircs
        so = self.main.getStateObserver()
        if so:
            so.event_UpdateInfo(n)


##############################################################################


class PeerHandler(DatagramProtocol):

    # Panic rate limit for broadcast traffic
    CHOKE_RATE = 100000   # bytes per second
    CHOKE_PERIOD = 5      # how many seconds to average over

    def __init__(self, main):
        self.main = main
        self.remap_ip = None

        self.choke_time = seconds() - self.CHOKE_PERIOD
        self.choke_reported = seconds() - 999

        # True iff we're shutting down after a socket failure.
        self.stopping_protocol = False


    def stopProtocol(self):
        # If this is the final termination, don't do anything.
        if not reactor.running:
            return

        self.main.showLoginStatus("UDP socket was reset.")

        # Otherwise, our UDP port randomly died, so try reconnecting.
        # Disable transmits during the shutdown.
        self.stopping_protocol = True
        try:
            self.main.shutdown(reconnect='instant')
        finally:
            self.stopping_protocol = False


    def getSocketState(self):
        # Figure out the state of our UDP socket.
        if self.stopping_protocol:
            return 'dying'
        elif not self.transport:
            return 'dead'
        elif hasattr(self.transport, "d"):
            return 'dying'
        else:
            return 'alive'


    def sendPacket(self, data, addr, broadcast=False):
        # Send a packet, passing it through the encrypter
        # returns False if an error occurs

        if self.stopping_protocol:
            # Still cleaning up after a socket asplosion.
            return False

        self.main.logPacket("%s -> %s:%d" % (data[:2], addr[0], addr[1]))
        data = self.main.pk_enc.encrypt(data)

        # For broadcast traffic, set a safety limit on data rate,
        # in order to protect the physical network from DoS attacks.

        if broadcast:
            now = seconds()
            self.choke_time = max(self.choke_time, now - self.CHOKE_PERIOD)

            penalty = (1.0 * len(data) *
                       self.CHOKE_PERIOD / self.CHOKE_RATE)

            # Have we used up the buffer time?
            if self.choke_time + penalty >= now:

                # Tell the user what's going on, but only once every
                # 10 seconds.
                if self.choke_reported < now - 10:
                    self.main.showLoginStatus(
                        "!!! Dropping broadcast packets due to "
                        "excessive flood !!!")
                    self.choke_reported = now

                # Don't send packet
                return False

            # Nibble something off the choke buffer
            self.choke_time += penalty

            self.main.logPacket(
                "choke=%f" % (now - (self.choke_time+penalty)))

        # Send the packet
        try:
            self.transport.write(data, addr)
        except socket.error:
            return False
        except RuntimeError:
            # Workaround the Twisted infinite recursion bug
            return False

        return True


    def datagramReceived(self, rawdata, addr, altport=False):

        ad = Ad().setAddrTuple(addr)

        if not ad.port:
            return

        # This will remap a router's internal IP to its external IP,
        # if the remapping is known.
        if self.remap_ip and ad.ip == self.remap_ip[0]:
            ad.orig_ip = ad.ip
            ad.ip = self.remap_ip[1]

        # Special handler for search results directly from DC
        if rawdata[:4] == '$SR ':
            dch = self.main.getOnlineDCH()
            if dch and ad.auth('sb', self.main):
                dch.pushSearchResult(rawdata)
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

            self.main.logPacket("%s <- %s:%d" % (kind, addr[0], addr[1]))

            # Make sure the sender's IP is permitted, but delay the check if
            # it's an initialize packet.
            if kind not in ('IQ', 'EC', 'IR', 'IC_alt'):
                if not ad.auth('sbx', self.main):
                    raise BadPacketError("Invalid source IP")

            try:
                method = getattr(self, 'handlePacket_%s' % kind)
            except AttributeError:
                raise BadPacketError("Unknown kind: %s" % kind)

            # arg1: Address the packet came from
            # arg2: The unencrypted packet
            method(ad, data)

        except (BadPacketError, BadTimingError), e:
            self.main.logPacket("Bad Packet/Timing: %s" % str(e))


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


    def decodeString2(self, data, max_len=1024):
        try:
            length, = struct.unpack('!H', data[:2])
        except struct.error:
            raise BadPacketError("Can't decode 2string")

        if length > max_len or len(data) < 2+length:
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
        nbs = [ipp for ipp, in nbs
               if Ad().setRawIPPort(ipp).auth('sx', self.main)]
        return nbs, rest


    def decodeNodeTimeList(self, data):
        nbs, rest = self.decodeString1(data, 6+4)
        nbs = [(ipp, age) for (ipp, age) in self.decodeChunkList('!6sI', nbs)
               if Ad().setRawIPPort(ipp).auth('sx', self.main)]
        return nbs, rest


    def checkSource(self, src_ipp, ad, exempt_ip=False):
        # Sometimes the source port number gets changed by NAT, but this
        # ensures that the source IP address matches the reported one.

        src_ad = Ad().setRawIPPort(src_ipp)

        if exempt_ip:
            kinds = 'sx'
        else:
            kinds = 's'

        if not src_ad.auth(kinds, self.main):
            raise BadPacketError("Invalid Source IP")

        if not src_ad.auth('b', self.main):
            raise BadPacketError("Source IP banned")

        if src_ad.ip != ad.ip:
            raise BadPacketError("Source IP mismatch")

        osm = self.main.osm
        if osm and src_ipp == osm.me.ipp:
            raise BadPacketError("Packet came from myself!?")

        self.main.state.refreshPeer(src_ad, 0)
        return src_ad


    def handleBroadcast(self, ad, data, check_cb, bridgey=False):
        (kind, nb_ipp, hop, flags, src_ipp, rest
         ) = self.decodePacket('!2s6sBB6s+', data)

        osm = self.main.osm
        if not osm:
            raise BadTimingError("Not ready to route '%s' packet" % kind)

        # Make sure nb_ipp agrees with the sender's IP
        self.checkSource(nb_ipp, ad, exempt_ip=True)

        # Make sure the src_ipp is valid.
        # Any broadcast which might be from a bridge is 'bridgey'
        src_ad = Ad().setRawIPPort(src_ipp)
        if bridgey:
            kinds = 'sbx'
        else:
            kinds = 'sb'
        if not src_ad.auth(kinds, self.main):
            raise BadPacketError("Invalid forwarded source IP")

        # Make sure this came from one of my ping neighbors.
        # This helps a little to prevent the injection of random broadcast
        # traffic into the network.
        try:
            if not osm.pgm.pnbs[nb_ipp].got_ack:
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

        try:
            # Filter all non-bridgey broadcasts from bridge nodes.
            if not bridgey and self.isFromBridgeNode(src_n, src_ipp):
                raise BadBroadcast("Bridge can't use " + kind)

            # Callback the check_cb function
            check_cb(src_n, src_ipp, rest)

        except BadBroadcast, e:
            self.main.logPacket("Bad Broadcast: %s" % str(e))

            # Mark that we've seen this message, but don't forward it.
            osm.mrm.newMessage(data, tries=0, nb_ipp=nb_ipp)

            # Ack and skip the rest
            self.sendAckPacket(nb_ipp, ACK_BROADCAST, ack_flags, ack_key)
            return

        except Reject:
            # check_cb told us to reject this broadcast
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
            # Start with the broadcast header
            packet = osm.mrm.broadcastHeader(kind, src_ipp, hop-1, flags)

            # Keep the rest of the message intact
            packet.append(rest)

            # Pass this message to MessageRoutingManager, so it will be
            # forwarded to all of my neighbors.
            osm.mrm.newMessage(''.join(packet), tries=2, nb_ipp=nb_ipp)

        # Ack the neighbor
        self.sendAckPacket(nb_ipp, ACK_BROADCAST, ack_flags, ack_key)

        # Update the original sender's age in the peer cache
        src_ad = Ad().setRawIPPort(src_ipp)
        self.main.state.refreshPeer(src_ad, 0)


    def handlePrivMsg(self, ad, data, cb):
        # Common code for handling private messages (PM, CA, CP)

        (kind, src_ipp, ack_key, src_nhash, dst_nhash, rest
         ) = self.decodePacket('!2s6s8s4s4s+', data)

        # If we're not on the network, ignore it.
        osm = self.main.osm
        if not osm:
            raise BadTimingError("Not ready to handle private message")

        ack_flags = 0

        try:
            # Make sure src_ipp agrees with the sender's IP
            self.checkSource(src_ipp, ad)

            # Make sure we're ready to receive it
            dch = self.main.getOnlineDCH()
            if not dch:
                raise Reject

            try:
                n = osm.lookup_ipp[src_ipp]
            except KeyError:
                raise Reject("Unknown node")

            if src_nhash != n.nickHash():
                raise Reject("Source nickhash mismatch")

            if dst_nhash != osm.me.nickHash():
                raise Reject("Dest nickhash mismatch")

            if n.pokePMKey(ack_key):
                # Haven't seen this message before, so handle it
                cb(dch, n, rest)

        except (BadPacketError, BadTimingError, Reject):
            ack_flags |= ACK_REJECT_BIT

        # Send acknowledgement
        self.sendAckPacket(src_ipp, ACK_PRIVATE, ack_flags, ack_key)


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
            self.main.logPacket("Outdated Status")
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
            self.main.logPacket("Outdated from-me packet")
            return True

        # If it's from my near future, then repair my packet number
        if 0 < (pktnum - osm.me.status_pktnum) % 0x100000000 < 2 * PKTNUM_BUF:
            osm.me.status_pktnum = pktnum

        # If I'm syncd, retransmit my status
        if osm.syncd:
            self.main.logPacket("Reacting to an impersonated status")
            osm.sendMyStatus(sendfull)

        return True


    def isFromBridgeNode(self, src_n, src_ipp):
        # Return true if a source matches a known bridge node.
        # This is not authenticated, so it should only be used to drop
        # packets that a bridge shouldn't be sending.
        osm = self.main.osm
        return ((src_n and src_n.bridge_data) or
                (osm and osm.bsm and src_ipp == osm.me.ipp))


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

        if ad.isPrivate() and my_ad.auth('sx', self.main):
            # If the request came from a private IP address, but was sent
            # toward a public IP address, then assume the sender node also
            # has the same public IP address.
            src_ad.ip = my_ad.ip
        else:
            src_ad.ip = ad.ip

        if not src_ad.auth('sx', self.main):
            ip_code = CODE_IP_FOREIGN
        elif not src_ad.auth('b', self.main):
            ip_code = CODE_IP_BANNED
        else:
            ip_code = CODE_IP_OK

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

        if ip_code != CODE_IP_OK:
            # For invalid IPs, send no neighbors, and a small peercache
            # just so they can try for a second opinion.
            IR_LEN = IC_LEN

        elif osm and osm.syncd:
            # Get a random sample of online nodes (plus me).
            indices = xrange(len(osm.nodes) + 1)
            try:
                indices = random.sample(indices, IR_LEN)
            except ValueError:
                pass

            # Remap the list of indices into a list of ipps.
            # For the one out-of-bounds index, fill in 'me'.
            def get_ipp(i):
                try:
                    return osm.nodes[i].ipp
                except IndexError:
                    return osm.me.ipp
            node_ipps = [get_ipp(i) for i in indices]

        elif osm:
            # Not syncd yet, don't add any online nodes
            pass

        elif (self.main.reconnect_dcall and self.main.accept_IQ_trigger
              and my_ad.auth('sx', self.main)):
            # If we've recently failed to connect, then go online
            # as the sole node on the network.  Then report our node ipp
            # so this other node can try to join us.

            self.main.addMyIPReport(src_ad, my_ad)
            self.main.startNodeSync(())

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

            ir_nodes.append(struct.pack('!6sI', ipp, int(age)))

        # Convert node_ipps into a set, for O(1) lookups
        node_ipps = set(node_ipps)

        # Grab the youngest peers in our cache.
        for when,ipp in state.getYoungestPeers(IR_LEN):

            # Add packet data to the outlist
            age = max(int(now - when), 0)

            pc_entry = struct.pack('!6sI', ipp, int(age))

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
        packet.append(struct.pack('!B', ip_code))

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
        packet.append(struct.pack('!B', ip_code))

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
        if ad.isPrivate():
            if not src_ad.auth('sx', self.main):
                raise BadPacketError("Invalid reported source IP")
        else:
            self.checkSource(src_ipp, ad, exempt_ip=True)

        pc, rest = self.decodeNodeTimeList(rest)

        if rest:
            raise BadPacketError("Extra data")

        if code not in (CODE_IP_OK, CODE_IP_FOREIGN, CODE_IP_BANNED):
            raise BadPacketError("Bad Response Code")

        if not self.main.icm:
            raise BadTimingError("Not in initial connection mode")

        self.main.icm.receivedInitResponse(src_ipp, myip, code, pc)


    def handlePacket_IR(self, ad, data):
        # Initialization Response
        (kind, src_ipp, myip, code, rest
         ) = self.decodePacket('!2s6s4sB+', data)

        src_ad = Ad().setRawIPPort(src_ipp)
        if ad.isPrivate():
            if not src_ad.auth('sx', self.main):
                raise BadPacketError("Invalid reported source IP")
        else:
            self.checkSource(src_ipp, ad, exempt_ip=True)

        # Node list, Peer Cache
        nd, rest = self.decodeNodeTimeList(rest)
        pc, rest = self.decodeNodeTimeList(rest)

        if rest:
            raise BadPacketError("Extra data")

        if code not in (CODE_IP_OK, CODE_IP_FOREIGN, CODE_IP_BANNED):
            raise BadPacketError("Bad Response Code")

        if not self.main.icm:
            raise BadTimingError("Not in initial connection mode")

        self.main.icm.receivedInitResponse(src_ipp, myip, code, pc, nd)


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

            if not (5 <= expire <= 30*60):
                raise BadPacketError("Expire time out of range")

            # Make sure this isn't about me
            if self.isMyStatus(src_ipp, pktnum, sendfull=True):
                raise BadBroadcast("Impersonating me")

            if self.isOutdatedStatus(src_n, pktnum):
                raise BadBroadcast("Outdated")

            n = osm.refreshNodeStatus(
                src_ipp, pktnum, expire, sesid, uptime, persist, nick, info)

            # They had a nick, now they don't.  This indicates a problem.
            # Stop forwarding and notify the user.
            if nick and not n.nick:
                raise Reject

        self.handleBroadcast(ad, data, check_cb)


    def handlePacket_NH(self, ad, data):
        # Broadcast: Node Status Hash (keep-alive)

        osm = self.main.osm

        def check_cb(src_n, src_ipp, rest):

            (pktnum, expire, infohash
             ) = self.decodePacket('!IH4s', rest)

            if not (5 <= expire <= 30*60):
                raise BadPacketError("Expire time out of range")

            # Make sure this isn't about me
            if self.isMyStatus(src_ipp, pktnum, sendfull=True):
                raise BadBroadcast("Impersonating me")

            if self.isOutdatedStatus(src_n, pktnum):
                raise BadBroadcast("Outdated")

            if osm.syncd:
                if src_n and src_n.infohash == infohash:
                    # We are syncd, and this node matches, so extend the
                    # expire timeout and keep forwarding.
                    src_n.status_pktnum = pktnum
                    osm.scheduleNodeExpire(src_n, expire + NODE_EXPIRE_EXTEND)
                    return

                else:
                    # Syncd, and we don't recognize it
                    raise Reject

            else:
                if not (src_n and src_n.expire_dcall):
                    # Not syncd, don't know enough about this node yet,
                    # so just forward blindly.
                    return

                elif src_n.infohash == infohash:
                    # We know about this node already, and the infohash
                    # matches, so extend timeout and keep forwarding
                    src_n.status_pktnum = pktnum
                    osm.scheduleNodeExpire(src_n, expire + NODE_EXPIRE_EXTEND)
                    return

                else:
                    # Not syncd, but we know the infohash is wrong.
                    raise Reject

        self.handleBroadcast(ad, data, check_cb)


    def handlePacket_NX(self, ad, data):
        # Broadcast: Node exiting

        osm = self.main.osm

        def check_cb(src_n, src_ipp, rest):

            (sesid,
             ) = self.decodePacket('!4s', rest)

            if osm.syncd:
                if src_ipp == osm.me.ipp and sesid == osm.me.sesid:
                    # Yikes! Make me a new session id and rebroadcast it.
                    osm.me.sesid = randbytes(4)
                    osm.reorderNodesList()

                    osm.sendMyStatus()
                    osm.pgm.scheduleMakeNewLinks()
                    raise BadBroadcast("Tried to exit me")

                if not src_n:
                    raise BadBroadcast("Node not online")

                if sesid != src_n.sesid:
                    raise BadBroadcast("Wrong session ID")

            elif not src_n:
                # Not syncd, and haven't seen this node yet.
                # Forward blindly
                return

            # Remove node
            osm.nodeExited(src_n, "Received NX")

        self.handleBroadcast(ad, data, check_cb)


    def handlePacket_NF(self, ad, data):
        # Broadcast: Node failure

        osm = self.main.osm

        def check_cb(src_n, src_ipp, rest):

            (pktnum, sesid,
             ) = self.decodePacket('!I4s', rest)

            # Make sure this isn't about me
            if self.isMyStatus(src_ipp, pktnum, sendfull=False):
                raise BadBroadcast("I'm not dead!")

            if not (src_n and src_n.expire_dcall):
                raise BadBroadcast("Nonexistent node")

            if src_n.sesid != sesid:
                raise BadBroadcast("Wrong session ID")

            if self.isOutdatedStatus(src_n, pktnum):
                raise BadBroadcast("Outdated")

            # Reduce the expiration time.  If that node isn't actually
            # dead, it will rebroadcast a status update to correct it.
            if (dcall_timeleft(src_n.expire_dcall) > NODE_EXPIRE_EXTEND):
                osm.scheduleNodeExpire(src_n, NODE_EXPIRE_EXTEND)

        self.handleBroadcast(ad, data, check_cb)


    def handlePacket_PF(self, ad, data):
        # Direct: Possible Falure (precursor to NF)

        osm = self.main.osm
        if not (osm and osm.syncd):
            raise BadTimingError("Not ready for PF")

        (kind, nb_ipp, dead_ipp, pktnum, sesid
         ) = self.decodePacket('!2s6s6sI4s', data)

        self.checkSource(nb_ipp, ad, exempt_ip=True)

        try:
            n = osm.lookup_ipp[dead_ipp]
        except KeyError:
            raise BadTimingError("PF received for not-online node")

        if n.sesid != sesid:
            raise BadTimingError("PF has the wrong session ID")

        if self.isOutdatedStatus(n, pktnum):
            raise BadTimingError("PF is outdated")

        osm.pgm.handleNodeFailure(n.ipp, nb_ipp)


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
                if nhash == osm.me.nickHash():
                    dch = self.main.getOnlineDCH()
                    if dch:
                        dch.pushStatus(
                            "*** Chat spoofing detected: %s" % text)
                raise BadBroadcast("Spoofed chat")

            if not osm.syncd:
                # Not syncd, forward blindly
                return

            if osm.isModerated():
                # Note: this may desync the sender's chat_pktnum, causing
                # their next valid message to be delayed by 2 seconds, but
                # it's better than broadcasting useless traffic.
                raise BadBroadcast("Chat is moderated")

            elif src_n and nhash == src_n.nickHash():
                osm.cms.addMessage(
                    src_n, pktnum, src_n.nick, text, flags)

            else:
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
                # Possibly a spoofed topic from me
                if nhash == osm.me.nickHash():
                    dch = self.main.getOnlineDCH()
                    if dch:
                        dch.pushStatus(
                            "*** Topic spoofing detected: %s" % topic)
                raise BadBroadcast("Spoofed topic")

            if not osm.syncd:
                # Not syncd, forward blindly
                return None

            if src_n and nhash == src_n.nickHash():
                osm.tm.gotTopic(src_n, topic)

            else:
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
                raise BadBroadcast("Spoofed search")

            if not osm.syncd:
                # Not syncd, forward blindly
                return

            if src_n:
                # Looks good
                dch = self.main.getOnlineDCH()
                if dch:
                    dch.pushSearchRequest(src_ipp, string)

            else:
                # From an invalid node
                raise Reject

        self.handleBroadcast(ad, data, check_cb)


    def handlePacket_AK(self, ad, data):
        # Direct: Acknowledgement

        osm = self.main.osm
        if not osm:
            raise BadTimingError("Not ready for AK packet")

        (kind, src_ipp, mode, flags, ack_key
         ) = self.decodePacket('!2s6sBB8s', data)

        self.checkSource(src_ipp, ad, exempt_ip=True)

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
                osm.mrm.receivedRejection(ack_key, src_ipp)

            # Tell MRM to stop retransmitting message to this neighbor
            osm.mrm.pokeMessage(ack_key, src_ipp)

        else:
            raise BadPacketError("Unknown AK mode")


    def handlePacket_CA(self, ad, data):
        # Direct: ConnectToMe

        def cb(dch, n, rest):
            # SSLHACK: newer Dtella versions have an extra flags byte, to allow
            #          for SSL connection requests.  Try to decode both forms.
            try:
                flags, port = self.decodePacket('!BH', rest)
            except BadPacketError:
                flags = 0
                port, = self.decodePacket('!H', rest)

            if port == 0:
                raise BadPacketError("Zero port")

            ad = Ad().setRawIPPort(n.ipp)
            ad.port = port
            use_ssl = bool(flags & USE_SSL_BIT)
            dch.pushConnectToMe(ad, use_ssl)

        self.handlePrivMsg(ad, data, cb)


    def handlePacket_CP(self, ad, data):
        # Direct: RevConnectToMe

        def cb(dch, n, rest):
            if rest:
                raise BadPacketError("Extra data")

            n.openRevConnectWindow()
            dch.pushRevConnectToMe(n.nick)

        self.handlePrivMsg(ad, data, cb)


    def handlePacket_PM(self, ad, data):
        # Direct: Private Message

        def cb(dch, n, rest):

            flags, rest = self.decodePacket('!B+', rest)

            text, rest = self.decodeString2(rest)

            if rest:
                raise BadPacketError("Extra data")

            notice = bool(flags & NOTICE_BIT)

            if notice:
                nick = "*N %s" % n.nick
                dch.pushChatMessage(nick, text)
            else:
                dch.pushPrivMsg(n.nick, text)

        self.handlePrivMsg(ad, data, cb)


    def handlePacket_PG(self, ad, data):
        # Direct: Local Ping

        osm = self.main.osm
        if not osm:
            raise BadTimingError("Not ready to receive pings yet")

        (kind, src_ipp, flags, rest
         ) = self.decodePacket('!2s6sB+', data)

        self.checkSource(src_ipp, ad, exempt_ip=True)

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

        # Hidden nodes shouldn't be getting sync requests.
        if self.main.hide_node:
            raise BadTimingError("Hidden node can't handle sync requests.")

        self.checkSource(nb_ipp, ad, exempt_ip=True)

        src_ad = Ad().setRawIPPort(src_ipp)
        if not src_ad.auth('sbx', self.main):
            raise BadPacketError("Invalid source IP")

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
        if not (osm and osm.sm):
            raise BadTimingError("Not ready for sync reply")

        (kind, src_ipp, pktnum, expire, sesid, uptime, flags, rest
         ) = self.decodePacket('!2s6sIH4sIB+', data)

        self.checkSource(src_ipp, ad)

        persist = bool(flags & PERSIST_BIT)

        nick, rest = self.decodeString1(rest)
        info, rest = self.decodeString1(rest)
        topic, rest = self.decodeString1(rest)

        c_nbs, rest = self.decodeNodeList(rest)
        u_nbs, rest = self.decodeNodeList(rest)

        if rest:
            raise BadPacketError("Extra data")

        if not (5 <= expire <= 30*60):
            raise BadPacketError("Expire time out of range")

        try:
            n = osm.lookup_ipp[src_ipp]
        except KeyError:
            n = None

        if self.isFromBridgeNode(n, src_ipp):
            raise BadPacketError("Bridge can't use YR")

        # Check for outdated status, in case an NS already arrived.
        if not self.isOutdatedStatus(n, pktnum):
            n = osm.refreshNodeStatus(
                src_ipp, pktnum, expire, sesid, uptime, persist, nick, info)

        if topic:
            osm.tm.receivedSyncTopic(n, topic)

        osm.sm.receivedSyncReply(src_ipp, c_nbs, u_nbs)


    def handlePacket_EC(self, ad, data):
        # Login echo

        osm = self.main.osm
        if not osm:
            raise BadTimingError("Not ready for login echo")

        (kind, rand
         ) = self.decodePacket('!2s8s', data)

        osm.receivedLoginEcho(ad, rand)


##############################################################################


class InitialContactManager(DatagramProtocol):
    # Scans through a list of known IP:Ports, and send a small ping to a
    # bunch of them.  Collect addresses of known online peers, and eventually
    # Pass off the list to the neighbor connection manager.


    class PeerInfo(object):
        __lt__ = lambda self,other: self.seen >  other.seen
        __le__ = lambda self,other: self.seen >= other.seen

        def __init__(self, ipp, seen):
            self.ipp = ipp
            self.seen = seen
            self.inheap = True
            self.timeout_dcall = None

            self.alt_reply = False
            self.bad_code = False


    def __init__(self, main):
        self.main = main
        self.deferred = None

        self.peers = {}  # {IPPort -> PeerInfo object}

        for ipp, seen in self.main.state.peers.iteritems():
            self.peers[ipp] = self.PeerInfo(ipp, seen)

        self.heap = self.peers.values()
        heapq.heapify(self.heap)

        self.waitreply = set()

        self.node_ipps = set()

        self.initrequest_dcall = None
        self.finish_dcall = None

        self.counters = {
            'good':0, 'foreign_ip':0, 'banned_ip':0, 'dead_port':0}


    def start(self):
        CHECK(self.deferred is None)
        self.deferred = defer.Deferred()

        self.main.showLoginStatus("Scanning For Online Nodes...", counter=1)

        # Listen on an arbitrary UDP port
        try:
            reactor.listenUDP(0, self)
        except twisted.internet.error.BindError:
            self.main.showLoginStatus("Failed to bind alt UDP port!")
            self.deferred.callback(('no_nodes', None))
        else:
            self.scheduleInitRequest()

        return self.deferred


    def newPeer(self, ipp, seen):
        # Called by PeerAddressManager

        try:
            p = self.peers[ipp]
        except KeyError:
            p = self.peers[ipp] = self.PeerInfo(ipp, seen)
            heapq.heappush(self.heap, p)
            self.scheduleInitRequest()
        else:
            if seen > p.seen:
                p.seen = seen

                # Bubble it up the heap.
                # This takes O(n) and uses an undocumented heapq function...
                if p.inheap:
                    heapq._siftdown(self.heap, 0, self.heap.index(p))


    def scheduleInitRequest(self):
        if not self.deferred:
            return
        if self.initrequest_dcall:
            return

        def cb():
            self.initrequest_dcall = None

            try:
                p = heapq.heappop(self.heap)
            except IndexError:
                self.checkStatus()
                return

            p.inheap = False

            ad = Ad().setRawIPPort(p.ipp)

            packet = ['IQ']
            packet.append(ad.getRawIP())
            packet.append(struct.pack('!H', self.main.state.udp_port))

            self.main.logPacket("IQ -> %s:%d" % ad.getAddrTuple())

            packet = self.main.pk_enc.encrypt(''.join(packet))

            try:
                # Send from the alternate port
                self.transport.write(packet, ad.getAddrTuple())
            except (AttributeError, socket.error):
                # Socket got funky, let the timeouts take care of it.
                pass
            except RuntimeError:
                # Workaround for the Twisted infinte recursion bug
                pass
            else:
                self.schedulePeerContactTimeout(p)

            self.initrequest_dcall = reactor.callLater(0.05, cb)

        self.initrequest_dcall = reactor.callLater(0, cb)


    def schedulePeerContactTimeout(self, p):

        CHECK(p not in self.waitreply)

        self.waitreply.add(p)

        def cb():
            p.timeout_dcall = None
            self.waitreply.remove(p)

            if p.alt_reply:
                self.recordResultType('dead_port')

            self.checkStatus()

        p.timeout_dcall = reactor.callLater(5.0, cb)


    def cancelPeerContactTimeout(self, p):
        try:
            self.waitreply.remove(p)
        except KeyError:
            return False

        dcall_discard(p, 'timeout_dcall')
        return True


    def receivedInitResponse(self, src_ipp, myip, code, pc, nd=None):

        # Get my own IP address
        my_ad = Ad().setRawIP(myip)

        self.main.logPacket("Init Response: myip=%s code=%d" %
                            (my_ad.getTextIP(), code))

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

            if not self.cancelPeerContactTimeout(p):
                # Wasn't waiting for this reply
                return

        # Add some new peers to our cache
        if pc:
            for ipp, age in pc:
                ad = Ad().setRawIPPort(ipp)
                self.main.state.refreshPeer(ad, age)

        if code != CODE_IP_OK:
            if not p.bad_code:
                p.bad_code = True

                if code == CODE_IP_FOREIGN:
                    self.recordResultType('foreign_ip')

                elif code == CODE_IP_BANNED:
                    self.recordResultType('banned_ip')

                self.cancelPeerContactTimeout(p)
                self.checkStatus()
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
        self.checkStatus()


    def recordResultType(self, kind):

        self.main.logPacket("Recording result: '%s'" % kind)
        self.counters[kind] += 1

        # Finish init after 5 seconds of inactivity

        if self.finish_dcall:
            self.finish_dcall.reset(5.0)
            return

        def cb():
            self.finish_dcall = None
            self.checkStatus(finished=True)

        self.finish_dcall = reactor.callLater(5.0, cb)


    def checkStatus(self, finished=False):

        # Stop if
        # - We receive 5 good replies, which make up >= 10% of the total
        # - We receive 50 total replies
        # - There is a 5-second gap of no new replies

        # After stopping, successful if good makes up >= 10% of the total

        total = sum(self.counters.values())
        ngood = self.counters['good']

        if not (self.heap or self.waitreply) or total >= 50:
            finished = True

        if finished:
            if total > 0 and ngood >= total * 0.10:
                self.initCompleted(good=True)
            else:
                self.initCompleted(good=False)

        elif ngood >= 5 and ngood >= total * 0.10:
            self.initCompleted(good=True)


    def initCompleted(self, good):
        self.shutdown()

        if good:
            self.deferred.callback(('good', self.node_ipps))

        else:
            # In a tie, prefer 'banned_ip' over 'foreign_ip', etc.
            rank = []
            i = 3
            for name in ('banned_ip', 'foreign_ip', 'dead_port'):
                rank.append( (self.counters[name], i, name) )
                i -= 1

            # Sort in descending order
            rank.sort(reverse=True)

            if rank[0][0] == 0:
                # Nobody replied
                self.deferred.callback(('no_nodes', None))

            else:
                # Return the name of the failure which occurred most
                self.deferred.callback((rank[0][2], None))


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
    implements(IDtellaNickNode)

    __lt__ = lambda self,other: self.dist <  other.dist
    __le__ = lambda self,other: self.dist <= other.dist

    # For statistics  (bridge nicks are False)
    is_peer = True

    # This will be redefined for bridge nodes
    bridge_data = None

    # Remember when we receive a RevConnect
    rcWindow_dcall = None


    def __init__(self, ipp):
        # Dtella Tracking stuff
        self.ipp = ipp            # 6-byte IP:Port
        self.sesid = None         # 4-byte session ID
        self.dist = None          # 16-byte md5 "distance"
        self.expire_dcall = None  # dcall for expiring stale nodes
        self.status_pktnum = None # Pktnum of last status update

        # ChatMessageSequencer stuff
        self.chatq = []
        self.chatq_base = None
        self.chatq_dcall = None

        # ack_key -> timeout DelayedCall
        self.msgkeys_out = {}
        self.msgkeys_in = {}

        # General Info
        self.nick = ''
        self.dcinfo = ''
        self.location = ''
        self.shared = 0

        self.dttag = ""

        self.infohash = None

        self.uptime = 0.0
        self.persist = False


    def calcDistance(self, me):
        # Distance is pseudo-random, to keep the network spread out

        my_key = me.ipp + me.sesid
        nb_key = self.ipp + self.sesid

        if my_key <= nb_key:
            self.dist = md5(my_key + nb_key).digest()
        else:
            self.dist = md5(nb_key + my_key).digest()


    def nickHash(self):
        # Return a 4-byte hash to prevent a transient nick mismapping

        if self.nick:
            return md5(self.ipp + self.sesid + self.nick).digest()[:4]
        else:
            return None


    def flags(self):
        flags = (self.persist and PERSIST_BIT)
        return struct.pack('!B', flags)



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


    def setInfo(self, info):

        old_dcinfo = self.dcinfo
        self.dcinfo, self.location, self.shared = (
            parse_incoming_info(SSLHACK_filter_flags(info)))

        if self.sesid is None:
            # Node is uninitialized
            self.infohash = None
        else:
            self.infohash = md5(
                self.sesid + self.flags() + self.nick + '|' + info
                ).digest()[:4]

        return self.dcinfo != old_dcinfo


    def setNoUser(self):
        # Wipe out the nick, and set info to contain only a Dt tag.
        self.nick = ''
        if self.dttag:
            self.setInfo("<%s>" % self.dttag)
        else:
            self.setInfo("")


    def openRevConnectWindow(self):
        # When get a RevConnect, create a 5-second window during
        # which errors are suppressed for outgoing connects.

        if self.rcWindow_dcall:
            self.rcWindow_dcall.reset(5.0)
            return

        def cb():
            del self.rcWindow_dcall

        self.rcWindow_dcall = reactor.callLater(5.0, cb)


    def checkRevConnectWindow(self):
        # If the RevConnect window is open, close it and return True.

        if self.rcWindow_dcall:
            self.rcWindow_dcall.cancel()
            del self.rcWindow_dcall
            return True
        else:
            return False


    def sendPrivateMessage(self, ph, ack_key, packet, fail_cb):
        # Send an ACK-able direct message to this node

        def cb(tries):

            if tries == 0:
                del self.msgkeys_out[ack_key]
                fail_cb("Timeout")
                return

            ad = Ad().setRawIPPort(self.ipp)
            ph.sendPacket(packet, ad.getAddrTuple())

            # Set timeout for outbound message
            # This will be cancelled if we receive an AK in time.
            dcall = reactor.callLater(1.0, cb, tries-1)
            dcall.pm_fail_cb = fail_cb
            self.msgkeys_out[ack_key] = dcall

        # Send it 3 times, then fail.
        cb(3)


    def receivedPrivateMessageAck(self, ack_key, reject):
        # Got an ACK for a private message

        try:
            dcall = self.msgkeys_out.pop(ack_key)
        except KeyError:
            return

        if reject:
            dcall.pm_fail_cb("Rejected")

        dcall.cancel()



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


    def event_ConnectToMe(self, main, port, use_ssl, fail_cb):

        osm = main.osm

        ack_key = self.getPMAckKey()
        flags = (use_ssl and USE_SSL_BIT)

        packet = ['CA']
        packet.append(osm.me.ipp)
        packet.append(ack_key)
        packet.append(osm.me.nickHash())
        packet.append(self.nickHash())
        if flags:
            # SSLHACK: This packet can't be understood by older Dtella
            #          versions, but stripping the SSL flag from MyINFO should
            #          prevent it from happening very often.
            packet.append(struct.pack('!B', flags))
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


    def nickRemoved(self, main):

        osm = main.osm

        # Cancel all pending privmsg timeouts
        for dcall in self.msgkeys_in.itervalues():
            dcall.cancel()

        for dcall in self.msgkeys_out.itervalues():
            dcall.cancel()

        self.msgkeys_in.clear()
        self.msgkeys_out.clear()

        osm.cms.clearQueue(self)

        # Bridge stuff
        if osm.bsm:
            osm.bsm.nickRemoved(self)


    def shutdown(self, main):
        dcall_discard(self, 'expire_dcall')
        dcall_discard(self, 'rcWindow_dcall')

        self.nickRemoved(main)

        if self.bridge_data:
            self.bridge_data.shutdown()

verifyClass(IDtellaNickNode, Node)


class MeNode(Node):

    info_out = ""

    def event_PrivateMessage(self, main, text, fail_cb):
        dch = main.getOnlineDCH()
        if dch:
            dch.pushPrivMsg(dch.nick, text)
        else:
            fail_cb("I'm not online!")

    def event_ConnectToMe(self, main, port, use_ssl, fail_cb):
        fail_cb("can't get files from yourself!")

    def event_RevConnectToMe(self, main, fail_cb):
        fail_cb("can't get files from yourself!")

verifyClass(IDtellaNickNode, MeNode)


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

            self.proxy_request = False


    def __init__(self, main):
        self.main = main
        self.uncontacted = RandSet()
        self.waitcount = 0
        self.info = {}

        for n in self.main.osm.nodes:
            s = self.info[n.ipp] = self.SyncInfo(n.ipp)
            s.in_total = True
            self.uncontacted.add(n.ipp)

        # Keep stats for how far along we are
        self.stats_done = 0
        self.stats_total = len(self.uncontacted)
        self.stats_lastbar = -1

        self.proxy_success = 0
        self.proxy_failed = 0

        self.main.showLoginStatus("Network Sync In Progress...", counter='inc')

        self.showProgress_dcall = None
        self.showProgress()

        # Start smaller to prevent an initial flood
        self.request_limit = 2

        self.advanceQueue()


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
        done = self.stats_done
        total = self.stats_total

        if total == 0:
            bar = MAX
        else:
            bar = (MAX * done) // total

        dcall_discard(self, 'showProgress_dcall')

        def cb():
            self.showProgress_dcall = None

            if bar == self.stats_lastbar:
                return

            self.stats_lastbar = bar

            progress = '>'*bar + '_'*(MAX-bar)
            self.main.showLoginStatus(
                "[%s] (%d/%d)" % (progress, done, total))

        if bar == MAX:
            # The final update should draw immediately
            cb()
        else:
            # Otherwise, only draw once per reactor loop
            self.showProgress_dcall = reactor.callLater(0, cb)


    def advanceQueue(self):

        # Raise request limit the first time it fills up
        if self.request_limit < 5 and self.waitcount >= 5:
            self.request_limit = 5

        while self.waitcount < self.request_limit:

            try:
                # Grab an arbitrary (semi-pseudorandom) uncontacted node.
                ipp = self.uncontacted.pop()
            except KeyError:
                # Ran out of nodes; see if we're done yet.
                if self.waitcount == 0:
                    dcall_discard(self, 'showProgress_dcall')
                    self.main.osm.syncComplete()
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
                self.scheduleSyncTimeout(s, proxy=True)
                self.updateStats(s, 0, +1)
            else:
                if ipp in self.uncontacted:
                    # Seen this node, had planned to ping it later.
                    # Pretend like we just pinged it now.
                    self.uncontacted.discard(ipp)
                    self.scheduleSyncTimeout(s, proxy=True)

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
                self.updateStats(s, 0, +1)

                self.advanceQueue()

        # Mark off that we've received a reply.
        try:
            s = self.info[src_ipp]
        except KeyError:
            s = self.info[src_ipp] = self.SyncInfo(src_ipp)

        # Keep track of NAT stats
        if s.proxy_request:
            s.proxy_request = False

            if s.fail_limit == 2:
                self.proxy_success += 1
            elif s.fail_limit == 1:
                self.proxy_failed += 1

            if (self.proxy_failed + self.proxy_success >= 10 and
                    self.proxy_failed > self.proxy_success):
                self.main.needPortForward()
                return

        self.uncontacted.discard(src_ipp)

        self.updateStats(s, +1, +1)
        self.showProgress()

        self.cancelSyncTimeout(s)


    def scheduleSyncTimeout(self, s, proxy=False):
        if s.timeout_dcall:
            return

        def cb():
            s.timeout_dcall = None
            self.waitcount -= 1

            s.fail_limit -= 1
            if s.fail_limit > 0:
                # Try again later
                self.uncontacted.add(s.ipp)
            else:
                self.updateStats(s, 0, -1)
                self.showProgress()

            self.advanceQueue()

        # Remember if this was requested first by another node
        if s.fail_limit == 2 and proxy:
            s.proxy_request = True

        self.waitcount += 1
        s.timeout_dcall = reactor.callLater(2.0, cb)


    def cancelSyncTimeout(self, s):
        if not s.timeout_dcall:
            return

        dcall_discard(s, 'timeout_dcall')
        self.waitcount -= 1
        self.advanceQueue()


    def shutdown(self):
        # Cancel all timeouts
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

        # BanManager
        self.banm = BanManager(main)

        # ChatMessageSequencer
        self.cms = ChatMessageSequencer(main)

        # BridgeClientManager / BridgeServerManager
        self.bcm = bcm
        self.bsm = bsm

        # SyncManager (init after contacting the first neighbor)
        self.sm = None

        # Init all these when sync is established:
        self.yqrm = None        # SyncRequestRoutingManager

        self.sendStatus_dcall = None

        # Keep track of outbound status rate limiting
        self.statusLimit_time = seconds() - 999
        self.statusLimit_dcall = None

        self.sendLoginEcho()

        # List of online nodes, sorted by random distance.
        self.nodes = []
        # Index of online nodes: ipp -> Node()
        self.lookup_ipp = {}

        for ipp in node_ipps:
            self.addNodeToNodesList(Node(ipp))

        # Initially, we'll just connect to random nodes.
        # This list will be sorted after syncing is finished.
        random.shuffle(self.nodes)

        if self.nodes:
            self.main.showLoginStatus(
                "Joining The Network.", counter='inc')
            self.pgm.scheduleMakeNewLinks()
        else:
            self.main.showLoginStatus(
                "Creating a new empty network.", counter='inc')
            self.syncComplete()


    def syncComplete(self):

        # Forget the SyncManager
        self.sm = None

        # Unconfirmed nodes (without an expiration) can't exist once the
        # network is syncd, so purge them from the nodes list.
        old_nodes = self.nodes
        self.nodes = []
        self.lookup_ipp.clear()
        for n in old_nodes:
            if n.expire_dcall:
                self.addNodeToNodesList(n)
            else:
                self.pgm.removeOutboundLink(n.ipp)

        self.reorderNodesList()

        # Get ready to handle Sync requests from other nodes
        self.yqrm = SyncRequestRoutingManager(self.main)
        self.syncd = True

        if self.bsm:
            self.bsm.syncComplete()

        # Connect to the "closest" neighbors
        self.pgm.scheduleMakeNewLinks()

        # Tell observers to get the nick list, topic, etc.
        self.main.stateChange_DtellaUp()

        self.main.showLoginStatus(
            "Sync Complete; You're Online!", counter='inc')


    def refreshNodeStatus(self, src_ipp, pktnum, expire, sesid, uptime,
                          persist, nick, info):
        CHECK(src_ipp != self.me.ipp)
        try:
            n = self.lookup_ipp[src_ipp]
            in_nodes = True
        except KeyError:
            n = Node(src_ipp)
            in_nodes = False

        self.main.logPacket("Status: %s %d (%s)" %
                            (hexlify(src_ipp), expire, nick))

        # Update the last-seen status packet number
        n.status_pktnum = pktnum

        # Change uptime to a fixed time when the node went up
        uptime = seconds() - uptime

        if self.syncd and in_nodes and n.sesid != sesid:
            # session ID changed; remove n from sorted nodes list
            # so that it will be reinserted into the correct place
            self.removeNodeFromNodesList(n)
            in_nodes = False

        # Update info
        n.sesid = sesid
        n.uptime = uptime
        n.persist = persist

        # Save version info
        n.dttag = parse_dtella_tag(info)

        if nick == n.nick:
            # Nick hasn't changed, just update info
            self.nkm.setInfoInList(n, info)

        else:
            # Nick has changed.

            # Remove old nick, if it's in there
            self.nkm.removeNode(n, "No DC client")

            # Run a sanity check on the new nick
            if nick and validateNick(nick) != '':
                # Malformed
                n.setNoUser()

            else:
                # Good nick, update the info
                n.nick = nick
                n.setInfo(info)

                # Try to add the new nick (no-op if the nick is empty)
                try:
                    self.nkm.addNode(n)
                except NickError:
                    n.setNoUser()

        # If n isn't in nodes list, then add it
        if not in_nodes:
            self.addNodeToNodesList(n)

        # Expire this node after the expected retransmit
        self.scheduleNodeExpire(n, expire + NODE_EXPIRE_EXTEND)

        # Possibly make this new node an outgoing link
        self.pgm.scheduleMakeNewLinks()

        # Return the node
        return n


    def nodeExited(self, n, reason):
        # Node n dropped off the network

        dcall_discard(n, 'expire_dcall')

        self.removeNodeFromNodesList(n)

        # Tell the TopicManager this node is leaving
        self.tm.checkLeavingNode(n)

        # If it's a bridge node, clean up the extra data
        if n.bridge_data:
            n.bridge_data.myNodeExited()
            del n.bridge_data

        # Remove from the nick mapping
        self.nkm.removeNode(n, reason)
        n.dttag = ""
        n.setNoUser()

        # Remove from the SyncManager, if it's active
        if self.sm:
            self.sm.giveUpNode(n.ipp)

        # Remove from outbound links; find more if needed.
        if self.pgm.removeOutboundLink(n.ipp):
            self.pgm.scheduleMakeNewLinks()


    def addNodeToNodesList(self, n):
        if self.syncd:
            n.calcDistance(self.me)
            bisect.insort(self.nodes, n)
        else:
            self.nodes.append(n)
        self.lookup_ipp[n.ipp] = n


    def removeNodeFromNodesList(self, n):
        # Remove a node from self.nodes.  It must exist.
        if self.syncd:
            i = bisect.bisect_left(self.nodes, n)
            CHECK(self.nodes[i] == n)
            del self.nodes[i]
        else:
            self.nodes.remove(n)
        del self.lookup_ipp[n.ipp]


    def reorderNodesList(self):
        # Recalculate and sort all nodes in the nodes list.
        for n in self.nodes:
            n.calcDistance(self.me)
        self.nodes.sort()


    def scheduleNodeExpire(self, n, when):
        # Schedule a timer for the given node to expire from the network

        if n.expire_dcall:
            n.expire_dcall.reset(when)
            return

        def cb():
            n.expire_dcall = None
            self.nodeExited(n, "Node Timeout")

        n.expire_dcall = reactor.callLater(when, cb)


    def getStatus(self):

        status = []

        # My Session ID
        status.append(self.me.sesid)

        # My Uptime and Flags
        status.append(struct.pack('!I', int(seconds() - self.me.uptime)))
        status.append(self.me.flags())

        # My Nick
        status.append(struct.pack('!B', len(self.me.nick)))
        status.append(self.me.nick)

        # My Info
        status.append(struct.pack('!B', len(self.me.info_out)))
        status.append(self.me.info_out)

        return status


    def updateMyInfo(self, send=False):
        # Grab my info from the DC client (if any) and maybe broadcast
        # it into the network.

        # If I'm a bridge, send bridge state instead.
        if self.bsm:
            if self.syncd:
                self.bsm.sendState()
            return

        dch = self.main.getOnlineDCH()

        me = self.me

        old_state = (me.nick, me.info_out, me.persist)

        me.persist = self.main.state.persistent
        me.dttag = get_version_string()

        if dch:
            me.info_out = dch.formatMyInfo()
            nick = dch.nick
        else:
            me.info_out = "<%s>" % me.dttag
            nick = ''

        if me.nick == nick:
            # Nick hasn't changed, just update info
            self.nkm.setInfoInList(me, me.info_out)

        else:
            # Nick has changed

            # Remove old node, if I'm in there
            self.nkm.removeNode(me, "Removing Myself")

            # Set new info
            me.nick = nick
            me.setInfo(me.info_out)

            # Add it back in, (no-op if my nick is empty)
            try:
                self.nkm.addNode(me)
            except NickError:
                # Nick collision.  Force the DC client to go invisible.
                # This will recursively call updateMyInfo with an empty nick.
                lines = [
                    "The nick <%s> is already in use on this network." % nick,
                    "Please change your nick, or type !REJOIN to try again."
                ]
                self.main.kickObserver(lines=lines, rejoin_time=None)
                return

        changed = (old_state != (me.nick, me.info_out, me.persist))

        if (send or changed) and self.syncd:
            self.sendMyStatus()


    def sendMyStatus(self, sendfull=True):
        # Immediately send my status, and keep sending updates over time.

        # This should never be called for a bridge.
        CHECK(not self.bsm)

        # Skip this stuff for hidden nodes.
        if self.main.hide_node:
            return

        self.checkStatusLimit()

        def cb(sendfull):
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
                packet.append(struct.pack('!H', int(expire)))
                packet.extend(self.getStatus())

            else:
                packet = self.mrm.broadcastHeader('NH', self.me.ipp)
                packet.append(pkt_id)

                packet.append(struct.pack('!H', expire))
                packet.append(self.me.infohash)

            self.mrm.newMessage(''.join(packet), tries=8)

        dcall_discard(self, 'sendStatus_dcall')
        cb(sendfull)


    def checkStatusLimit(self):
        # Do a sanity check on the rate of status updates that I'm sending.
        # If other nodes are causing me to trigger a lot, then something's
        # amiss, so go to sleep for a while.

        if self.statusLimit_dcall:
            return

        # Limit to 8 updates over 8 seconds
        now = seconds()
        self.statusLimit_time = max(self.statusLimit_time, now-8.0)
        self.statusLimit_time += 1.0

        if self.statusLimit_time < now:
            return

        def cb():
            self.statusLimit_dcall = None
            self.main.showLoginStatus("*** YIKES! Too many status updates!")
            self.main.shutdown(reconnect='max')

        self.statusLimit_dcall = reactor.callLater(0, cb)


    def isModerated(self):

        if self.bcm:
            return self.bcm.isModerated()

        if self.bsm:
            return self.bsm.isModerated()

        return False


    def sendLoginEcho(self):
        # Send a packet to myself, in order to determine how my router
        # (if any) reacts to loopback'd packets.

        def cb():
            self.loginEcho_dcall = None
            self.loginEcho_rand = None
            self.main.logPacket("No EC response")

        echorand = ''.join([chr(random.randint(0,255)) for i in range(8)])

        packet = ['EC']
        packet.append(echorand)

        ad = Ad().setRawIPPort(self.me.ipp)
        self.main.ph.sendPacket(''.join(packet), ad.getAddrTuple())

        self.loginEcho_dcall = reactor.callLater(3.0, cb)
        self.loginEcho_rand = echorand


    def receivedLoginEcho(self, ad, rand):
        if rand != self.loginEcho_rand:
            raise BadPacketError("EC Rand mismatch")

        myad = Ad().setRawIPPort(self.me.ipp)

        dcall_discard(self, 'loginEcho_dcall')
        self.loginEcho_rand = None

        if ad.ip == myad.ip:
            return

        if ad.isPrivate():
            # This matches an RFC1918 address, so it looks like a router.
            # Remap this address to my external IP in the future

            self.main.ph.remap_ip = (ad.ip, myad.ip)
            self.main.logPacket("EC: Remap %s->%s" %
                                (ad.getTextIP(), myad.getTextIP()))

        else:
            self.main.logPacket("EC: Not RFC1918")


    def makeExitPacket(self):
        packet = self.mrm.broadcastHeader('NX', self.me.ipp)
        packet.append(self.me.sesid)
        return ''.join(packet)


    def shutdown(self):

        # Cancel all the dcalls here
        dcall_discard(self, 'sendStatus_dcall')
        dcall_discard(self, 'statusLimit_dcall')

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
            n.shutdown(self.main)

        # Shut down the PingManager (and notify outbounds)
        if self.pgm:
            self.pgm.shutdown()

        # Shut down the BanManager (just cancels some dcalls)
        if self.banm:
            self.banm.shutdown()

        # Shut down the BridgeClientManager
        if self.bcm:
            self.bcm.shutdown()

        # Shut down the SyncRequestRoutingManager
        if self.yqrm:
            self.yqrm.shutdown()


##############################################################################


class PingManager(object):

    class PingNeighbor(object):
        def __init__(self, ipp):
            self.ipp = ipp
            self.outbound = False
            self.inbound = False
            self.ping_reqs = {}           # {ack_key: time sent}
            self.sendPing_dcall = None    # dcall for sending pings
            self.deadNb_dcall = None      # keep track of node failure
            self.got_ack = False
            self.u_got_ack = False
            self.ping_nbs = None
            self.avg_ping = None

        def stillAlive(self):
            # return True if the connection hasn't timed out yet
            return (self.sendPing_dcall and
                    self.sendPing_dcall.args[0] >= 0)

        def stronglyConnected(self):
            # return True if both ends are willing to accept broadcast traffic
            return (self.got_ack and self.u_got_ack)

    OUTLINK_GOAL = 3

    def __init__(self, main):
        self.main = main

        self.chopExcessLinks_dcall = None
        self.makeNewLinks_dcall = None

        # All of my ping neighbors: ipp -> PingNeighbor()
        self.pnbs = {}

        self.onlineTimeout_dcall = None
        self.scheduleOnlineTimeout()


    def receivedPing(self, src_ipp, uwant, u_got_ack, req_key, ack_key, nbs):

        osm = self.main.osm

        try:
            pn = self.pnbs[src_ipp]
        except KeyError:
            # If we're not fully online yet, then reject pings that we never
            # asked for.
            if not osm.syncd:
                raise BadTimingError("Not ready to accept pings yet")
            pn = self.pnbs[src_ipp] = self.PingNeighbor(src_ipp)

        CHECK(osm.syncd or pn.outbound)

        # Save list of this node's neighbors
        if nbs is not None:
            pn.ping_nbs = tuple(nbs)

        # Mark neighbor as inbound iff we got a uwant
        pn.inbound = uwant

        # If they requested an ACK, then we'll want to ping soon
        ping_now = bool(req_key)

        was_stronglyConnected = pn.stronglyConnected()

        # Keep track of whether the remote node has received an ack from us
        pn.u_got_ack = u_got_ack

        # If this ping contains an acknowledgement...
        if ack_key:
            try:
                sendtime = pn.ping_reqs[ack_key]
            except KeyError:
                raise BadPacketError("PG: unknown ack")

            # Keep track of ping delay
            delay = seconds() - sendtime
            self.main.logPacket("Ping: %f ms" % (delay * 1000.0))

            if pn.avg_ping is None:
                pn.avg_ping = delay
            else:
                pn.avg_ping = 0.8 * pn.avg_ping + 0.2 * delay

            # If we just got the first ack, then send a ping now to
            # send the GOTACK bit to neighbor
            if not pn.got_ack:
                pn.got_ack = True
                ping_now = True

            dcall_discard(pn, 'deadNb_dcall')

            # Schedule next ping in ~5 seconds
            self.pingWithRetransmit(pn, tries=4, later=True)

            # Got ack, so reset the online timeout
            self.scheduleOnlineTimeout()

        if not was_stronglyConnected and pn.stronglyConnected():

            # Just got strongly connected.
            if pn.outbound:
                self.scheduleChopExcessLinks()

            # If we have a good solid link, then the sync procedure
            # can begin.
            if not (osm.syncd or osm.sm):
                osm.sm = SyncManager(self.main)

        # Decide whether to request an ACK.  This is in a nested
        # function to make the logic more redable.
        def i_req():
            if not (pn.outbound or pn.inbound):
                # Don't request an ack for an unwanted connection
                return False

            if not pn.stillAlive():
                # Try to revitalize this connection
                return True

            if (ping_now and
                hasattr(pn.sendPing_dcall, 'ping_is_shortable') and
                dcall_timeleft(pn.sendPing_dcall) <= 1.0
                ):
                # We've got a REQ to send out in a very short time, so
                # send it out early with this packet we're sending already.
                return True

            return False

        if i_req():
            # Send a ping with ACK requesting + retransmits
            self.pingWithRetransmit(pn, tries=4, later=False, ack_key=req_key)

        elif ping_now:
            # Send a ping without an ACK request
            self.sendPing(pn, i_req=False, ack_key=req_key)

        # If neither end wants this connection, throw it away.
        if not (pn.outbound or pn.inbound):
            self.cancelInactiveLink(pn)


    def pingWithRetransmit(self, pn, tries, later, ack_key=None):

        dcall_discard(pn, 'sendPing_dcall')
        pn.ping_reqs.clear()

        def cb(tries):
            pn.sendPing_dcall = None

            # Send the ping
            self.sendPing(pn, True)

            # While tries is positive, use 1 second intervals.
            # When it hits zero, trigger a timeout.  As it goes negative,
            # pings get progressively more spaced out.

            if tries > 0:
                when = 1.0
            else:
                tries = max(tries, -7)
                when = 2.0 ** -tries  # max of 128 sec

            # Tweak the delay
            when *= random.uniform(0.9, 1.1)

            # Schedule retransmit
            pn.sendPing_dcall = reactor.callLater(when, cb, tries-1)

            # Just failed now
            if tries == 0:

                if self.main.osm.syncd and pn.got_ack:
                    # Note that we had to set sendPing_dcall before this.
                    self.handleNodeFailure(pn.ipp)

                pn.got_ack = False

                # If this was an inbound node, forget it.
                pn.inbound = False

                if pn.outbound:
                    # An outbound link just failed.  Go find another one.
                    self.scheduleMakeNewLinks()
                else:
                    # Neither side wants this link.  Clean up.
                    self.cancelInactiveLink(pn)

        if later:
            when = 5.0
        else:
            # Send first ping
            self.sendPing(pn, True, ack_key)
            tries -= 1
            when = 1.0

        # Schedule retransmit(s)
        when *= random.uniform(0.9, 1.1)
        pn.sendPing_dcall = reactor.callLater(when, cb, tries)

        # Leave a flag value in the dcall so we can test whether this
        # ping can be made a bit sooner
        if later:
            pn.sendPing_dcall.ping_is_shortable = True


    def cancelInactiveLink(self, pn):
        # Quietly remove an unwanted ping neighbor.
        CHECK(not pn.inbound)
        CHECK(not pn.outbound)
        dcall_discard(pn, 'sendPing_dcall')
        dcall_discard(pn, 'deadNb_dcall')
        del self.pnbs[pn.ipp]


    def instaKillNeighbor(self, pn):
        # Unconditionally drop neighbor connection (used for bans)
        iwant = pn.outbound
        pn.inbound = False
        pn.outbound = False
        self.cancelInactiveLink(pn)

        if iwant:
            self.scheduleMakeNewLinks()


    def handleNodeFailure(self, ipp, nb_ipp=None):
        osm = self.main.osm
        CHECK(osm and osm.syncd)

        # If this node isn't my neighbor, then don't even bother.
        try:
            pn = self.pnbs[ipp]
        except KeyError:
            return

        # Only accept a remote failure if that node is a neighbor of pn.
        if nb_ipp and pn.ping_nbs is not None and nb_ipp not in pn.ping_nbs:
            return

        # If this node's not online, don't bother.
        try:
            n = osm.lookup_ipp[ipp]
        except KeyError:
            return

        # A bridge node will just have to time out on its own
        if n.bridge_data:
            return

        # If the node's about to expire anyway, don't bother
        if dcall_timeleft(n.expire_dcall) <= NODE_EXPIRE_EXTEND * 1.1:
            return

        failedMe = not pn.stillAlive()

        # Trigger an NF message if I've experienced a failure, and:
        # - someone else just experienced a failure, or
        # - someone else experienced a failure recently, or
        # - I seem to be pn's only neighbor.

        pkt_id = struct.pack('!I', n.status_pktnum)

        if failedMe and (nb_ipp or pn.deadNb_dcall or pn.ping_nbs==()):

            dcall_discard(pn, 'deadNb_dcall')

            packet = osm.mrm.broadcastHeader('NF', n.ipp)
            packet.append(pkt_id)
            packet.append(n.sesid)

            try:
                osm.mrm.newMessage(''.join(packet), tries=2)
            except MessageCollisionError:
                # It's possible, but rare, that we've seen this NF before
                # without fully processing it.
                pass

            osm.scheduleNodeExpire(n, NODE_EXPIRE_EXTEND)

        elif nb_ipp:
            # If this failure was reported by someone else, then set the
            # deadNb_dcall, so when I detect a failure, I'll be sure of it.

            def cb():
                pn.deadNb_dcall = None

            dcall_discard(pn, 'deadNb_dcall')
            pn.deadNb_dcall = reactor.callLater(15.0, cb)

        elif pn.ping_nbs:
            # Reported by me, and pn has neighbors, so
            # Send Possible Failure message to pn's neighbors

            packet = ['PF']
            packet.append(osm.me.ipp)
            packet.append(n.ipp)
            packet.append(pkt_id)
            packet.append(n.sesid)
            packet = ''.join(packet)

            for nb_ipp in pn.ping_nbs:
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
                try:
                    pn = self.pnbs[n.ipp]
                except KeyError:
                    pn = self.pnbs[n.ipp] = self.PingNeighbor(n.ipp)

                if not pn.outbound:

                    if not pn.inbound:
                        # Completely new link
                        tries = 2

                    elif pn.stronglyConnected():
                        # An active inbound link is being marked as outbound,
                        # so we might want to close some other outbound
                        # link.  Note that this won't run until the next
                        # reactor loop.
                        self.scheduleChopExcessLinks()
                        tries = 4

                    else:
                        # Existing link, not strongly connected yet
                        tries = 2

                    pn.outbound = True
                    self.pingWithRetransmit(pn, tries=tries, later=False)

                if pn.outbound and pn.stillAlive():
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

            # Keep a set of unwanted outbound neighbors.  We will remove
            # wanted neighbors from this set, and kill what remains.
            unwanted = set(pn.ipp for pn in self.pnbs.itervalues()
                           if pn.outbound)
            n_alive = 0

            for n in osm.nodes:
                try:
                    pn = self.pnbs[n.ipp]
                    if not pn.outbound:
                        raise KeyError
                except KeyError:
                    # We ran out of nodes before hitting the target number
                    # of strongly connected nodes.  That means stuff's still
                    # connecting, and there's no need to remove anyone.
                    unwanted.clear()
                    break

                # This neighbor is NOT unwanted.
                unwanted.remove(pn.ipp)

                # Stop once we reach the desired number of outbound links.
                if pn.stronglyConnected():
                    n_alive += 1
                    if n_alive == self.OUTLINK_GOAL:
                        break

            # If any unwanted links remain, remove them.
            for ipp in unwanted:
                CHECK(self.removeOutboundLink(ipp))

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
            self.main.shutdown(reconnect='normal')

        self.onlineTimeout_dcall = reactor.callLater(ONLINE_TIMEOUT, cb)


    def removeOutboundLink(self, ipp):
        try:
            pn = self.pnbs[ipp]
        except KeyError:
            return False
        if not pn.outbound:
            return False

        # Send iwant=0 to neighbor
        pn.outbound = False
        if pn.inbound:
            self.pingWithRetransmit(pn, tries=4, later=False)
        else:
            self.sendPing(pn, i_req=False, ack_key=None)
            self.cancelInactiveLink(pn)
        return True


    def sendPing(self, pn, i_req, ack_key=None):
        # Transmit a single ping to the given node

        osm = self.main.osm

        # Expire old ack requests
        if pn.ping_reqs:
            now = seconds()
            for req_key, when in pn.ping_reqs.items():
                if now - when > 15.0:
                    del pn.ping_reqs[req_key]

        iwant = pn.outbound

        # For now, include neighbor list only when requesting an ack.
        nblist = i_req

        # Offline bit is set if this neighbor is not recognized.
        # (this just gets ignored, but it could be useful someday)
        offline = osm.syncd and (pn.ipp not in osm.lookup_ipp)

        # Build packet
        packet = ['PG']
        packet.append(osm.me.ipp)

        flags = ((iwant and IWANT_BIT)       |
                 (pn.got_ack and GOTACK_BIT) |
                 (i_req and REQ_BIT)         |
                 (bool(ack_key) and ACK_BIT) |
                 (nblist and NBLIST_BIT)     |
                 (offline and OFFLINE_BIT)
                 )

        packet.append(struct.pack('!B', flags))

        if i_req:
            # I'm requesting that this packet be acknowledged, so generate
            # a new req_key
            while True:
                req_key = randbytes(4)
                if req_key not in pn.ping_reqs:
                    break

            pn.ping_reqs[req_key] = seconds()
            packet.append(req_key)

        if ack_key:
            packet.append(ack_key)

        if nblist:
            if osm.syncd:
                # Grab my list of ping neighbors.
                nbs = [pn_it.ipp for pn_it in self.pnbs.itervalues()
                       if (pn_it.ipp != pn.ipp and
                           pn_it.ipp in osm.lookup_ipp and
                           pn_it.stronglyConnected())]

                # Don't bother sending more than 8
                nbs.sort()
                del nbs[8:]
            else:
                nbs = []

            packet.append(struct.pack("!B", len(nbs)))
            packet.extend(nbs)

        ad = Ad().setRawIPPort(pn.ipp)
        self.main.ph.sendPacket(''.join(packet), ad.getAddrTuple())


    def shutdown(self):
        dcall_discard(self, 'chopExcessLinks_dcall')
        dcall_discard(self, 'makeNewLinks_dcall')
        dcall_discard(self, 'onlineTimeout_dcall')

        outbounds = [pn for pn in self.pnbs.itervalues() if pn.outbound]

        for pn in self.pnbs.values():  # can't use itervalues
            pn.inbound = False
            pn.outbound = False
            self.cancelInactiveLink(pn)

        for pn in outbounds:
            self.sendPing(pn, i_req=False, ack_key=None)


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

            def cb():
                self.expire_dcall = None
                self.forgetTimeouts()
                del msgs[ack_key]

            self.expire_dcall = reactor.callLater(60.0, cb)


        def sendToNeighbor(self, nb_ipp, ph):
            # Pass this current message to the given neighbor

            if nb_ipp in self.nbs:
                # This neighbor has already seen our message
                return

            data = self.data
            tries = self.tries

            # If we're passing an NF to the node who's dying, then up the
            # number of retries to 8, because it's rather important.
            if data[0:2] == 'NF' and data[10:16] == nb_ipp:
                tries = 8

            def cb(tries):
                # Ack timeout callback

                # Make an attempt now
                if tries > 0:
                    addr = Ad().setRawIPPort(nb_ipp).getAddrTuple()
                    ph.sendPacket(data, addr, broadcast=True)

                # Reschedule another attempt
                if tries-1 > 0:
                    when = random.uniform(1.0, 2.0)
                    self.nbs[nb_ipp] = reactor.callLater(when, cb, tries-1)
                else:
                    self.nbs[nb_ipp] = None

            cb(tries)


        def forgetTimeouts(self):
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

        self.rcollide_last_NS = None
        self.rcollide_ipps = set()

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
            # need to verify pn.u_got_ack because it doesn't really matter
            # if they filter our traffic.
            sendto = [pn.ipp for pn in osm.pgm.pnbs.itervalues() if pn.got_ack]

            # For each message waiting to be sent, send to each of my
            # neighbors who needs it
            for m in self.outbox:
                for ipp in sendto:
                    m.sendToNeighbor(ipp, self.main.ph)

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
        return md5(data[0:2] + data[10:]).digest()[:8]


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

        # Tell the message that this neighbor acknowledged it.
        try:
            m.nbs[nb_ipp].cancel()
        except (KeyError, AttributeError):
            pass
        m.nbs[nb_ipp] = None

        return True


    def newMessage(self, data, tries, nb_ipp=None):
        # Forward a new message to my neighbors

        kind = data[0:2]
        ack_key = self.generateKey(data)

        if ack_key in self.msgs:
            raise MessageCollisionError("Duplicate " + kind)

        m = self.msgs[ack_key] = self.Message(data, tries)
        self.pokeMessage(ack_key, nb_ipp)

        osm = self.main.osm

        if data[10:16] == osm.me.ipp:
            CHECK(not self.main.hide_node)

            if kind in ('NH','CH','SQ','TP'):
                # Save the current status_pktnum for this message, because
                # it's useful if we receive a Reject message later.
                m.status_pktnum = osm.me.status_pktnum

            elif kind == 'NS':
                # Save my last NS message, so that if it gets rejected,
                # it can be interpreted as a remote nick collision.
                self.rcollide_last_NS = m
                self.rcollide_ipps.clear()

        if tries > 0:
            # Put message into the outbox
            self.outbox.append(m)
            self.scheduleSendMessages()


    def receivedRejection(self, ack_key, ipp):
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

        if m is self.rcollide_last_NS:
            # Remote nick collision might have occurred

            self.rcollide_ipps.add(ipp)

            if len(self.rcollide_ipps) > 1:
                # Multiple nodes have reported a problem, so tell the user.
                dch = self.main.getOnlineDCH()
                if dch:
                    dch.remoteNickCollision()

                # No more reports until next time
                self.rcollide_last_NS = None
                self.rcollide_ipps.clear()

        if osm.me.status_pktnum == m.status_pktnum:
            # One of my hash-containing broadcasts has been rejected, so
            # send my full status to refresh everyone.
            # (Note: m.status_pktnum is None for irrelevant messages.)
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
            m.forgetTimeouts()

        self.msgs.clear()

        # Immediately broadcast NX to my neighbors

        ph = self.main.ph
        osm = self.main.osm

        if osm and osm.syncd and not self.main.hide_node:
            packet = osm.makeExitPacket()
            for pn in osm.pgm.pnbs.itervalues():
                ad = Ad().setRawIPPort(pn.ipp)
                ph.sendPacket(packet, ad.getAddrTuple(), broadcast=True)


##############################################################################


class SyncRequestRoutingManager(object):

    class Message(object):

        def __init__(self):
            self.nbs = {}   # {ipp: max hop count}
            self.expire_dcall = None


        def scheduleExpire(self, msgs, key):
            if self.expire_dcall:
                self.expire_dcall.reset(180.0)
                return

            def cb():
                del msgs[key]

            self.expire_dcall = reactor.callLater(180.0, cb)


    def __init__(self, main):
        self.main = main
        self.msgs = {}


    def receivedSyncRequest(self, nb_ipp, src_ipp, sesid, hop, timedout):
        osm = self.main.osm
        ph  = self.main.ph

        key = (src_ipp, sesid)

        # Get ipp of all syncd neighbors who we've heard from recently
        CHECK(osm and osm.syncd)
        my_nbs = [pn.ipp for pn in osm.pgm.pnbs.itervalues()
                  if pn.got_ack and pn.ipp in osm.lookup_ipp]

        # Put neighbors in random order
        random.shuffle(my_nbs)

        # See if we've seen this sync message before
        try:
            m = self.msgs[key]
            isnew = False
        except KeyError:
            m = self.msgs[key] = self.Message()
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

            for ipp in my_nbs:
                # If we've already contacted enough nodes, or we know this
                # node has already been contacted with a higher hop count,
                # then don't forward the sync request to it.
                try:
                    if len(cont) >= 3 or m.nbs[ipp] >= hop-1:
                        uncont.append(ipp)
                        continue
                except KeyError:
                    pass

                cont.append(ipp)
                m.nbs[ipp] = hop-1

                ad = Ad().setRawIPPort(ipp)
                ph.sendPacket(packet, ad.getAddrTuple(), broadcast=True)

        else:
            # no hops left
            cont = []
            uncont = my_nbs

        # Cut off after 16 nodes, just in case
        uncont = uncont[:16]

        if isnew or timedout:
            self.sendSyncReply(src_ipp, cont, uncont)


    def sendSyncReply(self, src_ipp, cont, uncont):
        ad = Ad().setRawIPPort(src_ipp)
        osm = self.main.osm

        CHECK(osm and osm.syncd)

        # Build Packet
        packet = ['YR']

        # My IP:Port
        packet.append(osm.me.ipp)

        # My last pktnum
        packet.append(struct.pack('!I', osm.me.status_pktnum))

        # If we send a YR which is almost expired, followed closely by
        # an NH with an extended expire time, then a race condition exists,
        # because the target could discard the NH before receiving the YR.

        # So, if we're about to expire, go send a status update NOW so that
        # we'll have a big expire time to give to the target.

        expire = dcall_timeleft(osm.sendStatus_dcall)
        if expire <= 5.0:
            osm.sendMyStatus(sendfull=False)
            expire = dcall_timeleft(osm.sendStatus_dcall)

        # Exact time left before my status expires.
        # (The receiver will add a few buffer seconds.)
        packet.append(struct.pack('!H', int(expire)))

        # Session ID, Uptime, Flags, Nick, Info
        packet.extend(osm.getStatus())

        # If I think I set the topic last, then put it in here.
        # It's up to the receiving end whether they'll believe me.
        if osm.tm.topic_node is osm.me:
            topic = osm.tm.topic
        else:
            topic = ""
        packet.append(struct.pack('!B', len(topic)))
        packet.append(topic)

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
    # If chat messages arrive out-of-order, this will delay
    # some messages for a couple seconds waiting for packets to arrive.


    def __init__(self, main):
        self.main = main


    def addMessage(self, n, pktnum, nick, text, flags):

        if not self.main.getStateObserver():
            return

        # False == the bridge wants us to queue everything
        unlocked = not hasattr(n, 'dns_pending')

        msg = (nick, text, flags)

        if n.chatq_base is None:
            n.chatq_base = pktnum

        # How far forward/back to accept messages
        FUZZ = 10

        # Find the pktnum index relative to the current base.
        # If it's slightly older, this will be negative.
        idx = ((pktnum - n.chatq_base + FUZZ) % 0x100000000) - FUZZ

        if idx < 0:
            # Older message, send out of order
            if unlocked:
                self.sendMessage(n, msg)

        elif idx >= FUZZ:
            # Way out there; put this at the end and dump everything
            if unlocked:
                n.chatq.append(msg)
                self.flushQueue(n)

        else:
            # From the near future: (0 <= idx < PKTNUM_BUF)

            # Make sure the queue is big enough;
            # put a timestamp in the empty spaces.
            extra = (idx - len(n.chatq)) + 1
            if extra > 0:
                n.chatq.extend([seconds()] * extra)

            # Insert the current message into its space
            if (type(n.chatq[idx]) is float):
                n.chatq[idx] = msg

            # Possible spoof?
            # Don't know which one's real, so flush the queue and move on.
            elif n.chatq[idx] != msg:
                if unlocked:
                    n.chatq.insert(idx + 1, msg)
                    self.flushQueue(n)
                    return

            if unlocked:
                self.advanceQueue(n)


    def advanceQueue(self, n):

        # Send first block of available messages
        while n.chatq and (type(n.chatq[0]) is not float):
            msg = n.chatq.pop(0)
            n.chatq_base = (n.chatq_base + 1) % 0x100000000
            self.sendMessage(n, msg)

        dcall_discard(n, 'chatq_dcall')

        # If any messages remain, send them later.
        if not n.chatq:
            return

        def cb():
            n.chatq_dcall = None

            # Forget any missing messages at the beginning
            while n.chatq and (type(n.chatq[0]) is float):
                n.chatq.pop(0)
                n.chatq_base = (n.chatq_base + 1) % 0x100000000

            # Send the first block of available messages
            self.advanceQueue(n)

        # The first queue entry contains a timestamp.
        # Let the gap survive for 2 seconds total.
        when = max(0, n.chatq[0] + 2.0 - seconds())
        n.chatq_dcall = reactor.callLater(when, cb)


    def flushQueue(self, n):
        # Send all the messages in the queue, in order
        for msg in n.chatq:
            if (type(msg) is not float):
                self.sendMessage(n, msg)

        self.clearQueue(n)


    def clearQueue(self, n):
        # Reset everything to normal
        del n.chatq[:]
        dcall_discard(n, 'chatq_dcall')
        n.chatq_base = None


    def sendMessage(self, n, msg):
        so = self.main.getStateObserver()
        if so:
            nick, text, flags = msg
            so.event_ChatMessage(n, nick, text, flags)


##############################################################################


class BanManager(object):

    def __init__(self, main):
        self.main = main
        self.rebuild_bans_dcall = None
        self.ban_matcher = SubnetMatcher()
        self.isBanned = self.ban_matcher.containsIP

    def scheduleRebuildBans(self):
        if self.rebuild_bans_dcall:
            return

        def cb():
            self.rebuild_bans_dcall = None
            osm = self.main.osm
            self.ban_matcher.clear()

            # Get all bans from bridges.
            if osm.bcm:
                for bridge in osm.bcm.bridges:
                    for b in bridge.bans.itervalues():
                        if b.enable:
                            self.ban_matcher.addRange(b.ipmask)

            # If I'm a bridge, get bans from IRC.
            if osm.bsm and self.main.ism:
                for ipmask in self.main.ism.bans:
                    self.ban_matcher.addRange(ipmask)

            self.enforceAllBans()

        # This time is slightly above zero, so that broadcast deliveries
        # will have a chance to take place before carnage occurs.
        self.rebuild_bans_dcall = reactor.callLater(1.0, cb)

    def enforceAllBans(self):
        osm = self.main.osm

        # Check all the online nodes.
        for n in list(osm.nodes):
            int_ip = Ad().setRawIPPort(n.ipp).getIntIP()
            if self.isBanned(int_ip):
                osm.nodeExited(n, "Node Banned")

        # Check my ping neighbors.
        for pn in osm.pgm.pnbs.values():  # can't use itervalues
            int_ip = Ad().setRawIPPort(pn.ipp).getIntIP()
            if self.isBanned(int_ip):
                osm.pgm.instaKillNeighbor(pn)

        # Check myself
        if not osm.bsm:
            int_ip = Ad().setRawIPPort(osm.me.ipp).getIntIP()
            if self.isBanned(int_ip):
                self.main.showLoginStatus("You were banned.")
                self.main.shutdown(reconnect='max')

    def shutdown(self):
        dcall_discard(self, 'rebuild_bans_dcall')


##############################################################################


class TopicManager(object):

    def __init__(self, main):
        self.main = main
        self.topic = ""
        self.topic_whoset = ""
        self.topic_node = None
        self.waiting = True


    def gotTopic(self, n, topic):
        self.updateTopic(n, n.nick, topic, changed=True)


    def receivedSyncTopic(self, n, topic):
        # Topic arrived from a YR packet
        if self.waiting:
            self.updateTopic(n, n.nick, topic, changed=False)


    def updateTopic(self, n, nick, topic, changed):

        # Don't want any more SyncTopics
        self.waiting = False

        # Don't allow a non-bridge node to override a bridge's topic
        if self.topic_node and n:
            if self.topic_node.bridge_data and (not n.bridge_data):
                return False

        # Sanitize the topic
        topic = topic[:255].replace('\r','').replace('\n','')

        # Get old topic
        old_topic = self.topic

        # Store stuff
        self.topic = topic
        self.topic_whoset = nick
        self.topic_node = n

        # Without DC, there's nothing to say
        dch = self.main.getOnlineDCH()
        if not dch:
            return True

        # If it's changed, push it to the title bar
        if topic != old_topic:
            dch.pushTopic(topic)

        # If a change was reported, tell the user that it changed.
        if changed and nick:
            dch.pushStatus("%s changed the topic to: %s" % (nick, topic))

        # If a change wasn't reported, but it's new to us, and it's not
        # empty, then just say what the topic is.
        if not changed and topic and topic != old_topic:
            dch.pushStatus(self.getFormattedTopic())

        return True


    def broadcastNewTopic(self, topic):
        osm = self.main.osm

        if len(topic) > 255:
            topic = topic[:255]

        # Update topic locally
        if not self.updateTopic(osm.me, osm.me.nick, topic, changed=True):

            # Topic is controlled by a bridge node
            self.topic_node.bridge_data.sendTopicChange(topic)
            return

        packet = osm.mrm.broadcastHeader('TP', osm.me.ipp)
        packet.append(struct.pack('!I', osm.mrm.getPacketNumber_search()))

        packet.append(osm.me.nickHash())
        packet.append(struct.pack('!B', len(topic)))
        packet.append(topic)

        osm.mrm.newMessage(''.join(packet), tries=4)


    def getFormattedTopic(self):

        if not self.topic:
            return "There is currently no topic set."

        text = "The topic is: %s" % self.topic

        if self.topic_node and self.topic_node.nick:
            whoset = self.topic_node.nick
        else:
            whoset = self.topic_whoset

        if whoset:
            text += " (set by %s)" % whoset

        return text


    def checkLeavingNode(self, n):
        # If the node who set the topic leaves, wipe out the topic
        if self.topic_node is n:
            self.updateTopic(None, "", "", changed=False)


##############################################################################


class DtellaMain_Base(object):

    def __init__(self):

        self.myip_reports = []

        self.reconnect_dcall = None

        self.reconnect_interval = RECONNECT_RANGE[0]

        # Initial Connection Manager
        self.icm = None

        # Neighbor Connection Manager
        self.osm = None

        self.accept_IQ_trigger = False

        # Pakcet Encoder
        self.pk_enc = dtella.common.crypto.PacketEncoder(local.network_key)

        # Register a function that runs before shutting down
        reactor.addSystemEventTrigger('before', 'shutdown',
                                      self.cleanupOnExit)

        # Set to True to prevent this node from broadcasting.
        self.hide_node = False


    def cleanupOnExit(self):
        raise NotImplemented("Override me!")


    def reconnectDesired(self):
        raise NotImplemented("Override me!")


    def startConnecting(self):
        raise NotImplemented("Override me!")


    def startInitialContact(self):
        # If all the conditions are right, start connection procedure

        CHECK(not (self.icm or self.osm))

        dcall_discard(self, 'reconnect_dcall')

        def cb(result):
            self.icm = None
            result, node_ipps = result

            if result == 'good':
                self.startNodeSync(node_ipps)

            elif result == 'banned_ip':
                self.showLoginStatus(
                    "Your IP seems to be banned from this network.")
                self.shutdown(reconnect='max')

            elif result == 'foreign_ip':
                self.showLoginStatus(
                    "Your IP address is not authorized to use this network.")
                self.shutdown(reconnect='max')

            elif result == 'dead_port':
                self.needPortForward()

            elif result == 'no_nodes':
                self.showLoginStatus(
                    "No online nodes found.")
                self.shutdown(reconnect='normal')

                # If we receive an IQ packet after finding no nodes, then
                # assume we're a root node and form an empty network
                if not self.hide_node:
                    self.accept_IQ_trigger = True

            else:
                # Impossible result
                CHECK(False)

        self.ph.remap_ip = None
        self.icm = InitialContactManager(self)
        self.icm.start().addCallback(cb)


    def needPortForward(self):
        self.showLoginStatus(
            "*** UDP PORT FORWARD REQUIRED ***")

        text = (
            "In order for Dtella to communicate properly, it needs to "
            "receive UDP traffic from the Internet.  Dtella is currently "
            "listening on UDP port %d, but the packets appear to be "
            "getting blocked, most likely by a firewall or a router.  "
            "If this is the case, then you will have to configure your "
            "firewall or router to allow UDP traffic through on this "
            "port.  You may tell Dtella to use a different port from "
            "now on by typing !UDP followed by a number."
            % self.state.udp_port
            )

        for line in word_wrap(text):
            self.showLoginStatus(line)

        self.shutdown(reconnect='max')


    def startNodeSync(self, node_ipps):
        # Determine my IP address and enable the osm

        CHECK(not (self.icm or self.osm))

        # Reset the reconnect interval
        self.reconnect_interval = RECONNECT_RANGE[0]
        dcall_discard(self, 'reconnect_dcall')

        # Get my address and port
        try:
            my_ipp = self.selectMyIP()
        except ValueError:
            self.showLoginStatus("Can't determine my own IP?!")
            return

        # Look up my location string
        if local.use_locations:
            self.queryLocation(my_ipp)

        # Get Bridge Client/Server Manager, or nothing.
        b = self.getBridgeManager()

        # Enable the object that keeps us online
        self.osm = OnlineStateManager(self, my_ipp, node_ipps, **b)


    def getBridgeManager(self):
        raise NotImplemented("Override me!")


    def queryLocation(self, my_ipp):
        raise NotImplemented("Override me!")


    def logPacket(self, text):
        raise NotImplemented("Override me!")


    def showLoginStatus(self, text, counter=None):
        raise NotImplemented("Override me!")


    def shutdown(self, reconnect):
        # Do a total shutdown of this Dtella node

        # It's possible for these both to be None, but we still
        # want to reconnect.  (i.e. after an ICM failure)
        if (self.icm or self.osm):
            self.showLoginStatus("Shutting down.")

        dcall_discard(self, 'reconnect_dcall')
        self.accept_IQ_trigger = False

        # Shut down InitialContactManager
        if self.icm:
            self.icm.shutdown()
            self.icm = None

        # Shut down OnlineStateManager
        if self.osm:
            # Notify any observers that all the nicks are gone.
            if self.osm.syncd:
                self.stateChange_DtellaDown()

            self.osm.shutdown()
            self.osm = None

        # Notify some random handlers of the shutdown
        self.afterShutdownHandlers()

        # Schedule a Reconnect (maybe) ...

        # Check if a reconnect makes sense right now
        if not self.reconnectDesired():
            return

        if reconnect == 'no':
            return
        elif reconnect == 'max':
            self.reconnect_interval = RECONNECT_RANGE[1]
        else:
            CHECK(reconnect in ('normal', 'instant'))

        if reconnect == 'instant':
            # Just do an instant reconnect without saying anything.
            when = 0
            self.reconnect_interval = RECONNECT_RANGE[0]

        else:
            # Decide how long to wait before reconnecting
            when = self.reconnect_interval * random.uniform(0.8, 1.2)

            # Increase the reconnect interval logarithmically
            self.reconnect_interval = min(self.reconnect_interval * 1.5,
                                          RECONNECT_RANGE[1])

            self.showLoginStatus("--")
            self.showLoginStatus(
                "Next reconnect attempt in %d seconds." % when)

        def cb():
            self.reconnect_dcall = None
            self.startConnecting()

        self.reconnect_dcall = reactor.callLater(when, cb)


    def afterShutdownHandlers(self):
        raise NotImplemented("Override me!")


    def getOnlineDCH(self):
        raise NotImplemented("Override me!")


    def getStateObserver(self):
        raise NotImplemented("Override me!")


    def kickObserver(self, lines, rejoin_time):
        so = self.getStateObserver()
        CHECK(so)

        # Act as if Dtella is shutting down.
        self.stateChange_DtellaDown()

        # Force the observer to go invisible, with a kick message.
        so.event_KickMe(lines, rejoin_time)

        # Send empty state to Dtella.
        self.stateChange_ObserverDown()


    def stateChange_ObserverUp(self):
        # Called after a DC client / IRC server / etc. has become available.
        osm = self.osm
        if osm and osm.syncd:
            self.osm.updateMyInfo()

        # Make sure the observer's still online, because a nick collison
        # in updateMyInfo could have killed it.
        so = self.getStateObserver()
        if so:
            so.event_DtellaUp()


    def stateChange_ObserverDown(self):
        # Called after a DC client / IRC server / etc. has gone away.
        CHECK(not self.getStateObserver())

        osm = self.osm
        if osm and osm.syncd:
            osm.updateMyInfo()

            # Cancel all nick-specific messages.
            for n in osm.nodes:
                n.nickRemoved(self)


    def stateChange_DtellaUp(self):
        # Called after Dtella has finished syncing.
        osm = self.osm
        CHECK(osm and osm.syncd)
        osm.updateMyInfo(send=True)

        so = self.getStateObserver()
        if so:
            so.event_DtellaUp()


    def stateChange_DtellaDown(self):
        # Called before Dtella network shuts down.
        so = self.getStateObserver()
        if so:
            # Remove every nick.
            for n in self.osm.nkm.nickmap.itervalues():
                so.event_RemoveNick(n, "Removing All Nicks")
            so.event_DtellaDown()


    def addMyIPReport(self, from_ad, my_ad):
        # fromip = the IP who sent us this guess
        # myip = the IP that seems to belong to us

        if not (from_ad.auth('sx', self) and my_ad.auth('sx', self)):
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


