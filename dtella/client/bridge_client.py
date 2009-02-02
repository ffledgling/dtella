"""
Dtella - Bridge Client Module
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

from twisted.internet import reactor

import dtella.common.core as core
from dtella.common.core import (BadTimingError, BadPacketError, BadBroadcast,
                                Reject, NickError)

from dtella.common.util import RandSet, dcall_discard, parse_incoming_info

import dtella.common.ipv4 as ipv4
from dtella.common.ipv4 import Ad

from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
from hashlib import md5
import struct
import random

from zope.interface import implements
from zope.interface.verify import verifyClass
from dtella.common.interfaces import IDtellaNickNode

class ChunkError(Exception):
    pass

class BridgeClientProtocol(core.PeerHandler):

    def verifySignature(self, rsa_obj, data, sig, broadcast):
        # 0:2 = kind
        # 2:8 = neighbor ipp
        # 8:9 = hop limit
        # 9:10 = flags
        # 10:16 = source ipp
        # 16: = "the rest"

        if not rsa_obj:
            return False

        # Grab the kind, skip over the header, and get everything up
        # to but not including the signature.
        if broadcast:
            body = data[0:2] + data[10:-len(sig)]
        else:
            body = data[:-len(sig)]

        data_hash = md5(body).digest()
        sig_tuple = (bytes_to_long(sig),)

        try:
            return rsa_obj.verify(data_hash, sig_tuple)
        except:
            return False


    def isOutdatedBridgeStatus(self, n, pktnum):

        if n is None:
            # Can't be outdated if we've never seen it before
            return False

        if not n.bridge_data:
            # Node isn't a bridge (yet), so it's not outdated
            return False

        if n.bridge_data.status_pktnum > pktnum:
            # We've received a newer pktnum before, so it IS outdated.
            return True

        return False


    def handlePacket_BS(self, ad, data):

        osm = self.main.osm

        def check_cb(src_n, src_ipp, rest):

            (pktnum, expire, sesid, uptime, flags, rest
             ) = self.decodePacket('!QH4sIB+', rest)

            persist = bool(flags & core.PERSIST_BIT)

            (hashes, rest
             ) = self.decodeString1(rest, 16)
            
            hashes = [h for h, in self.decodeChunkList('!16s', hashes)]

            (pubkey, signature
             ) = self.decodeString2(rest)

            if not (expire <= 30*60):
                raise BadPacketError("Expire time out of range")

            # If the signed message is too old, discard it.
            if osm.bcm.signatureExpired(pktnum):
                raise BadBroadcast

            # If we've received a newer status update, then this is useless.
            if self.isOutdatedBridgeStatus(src_n, pktnum):
                raise BadBroadcast

            # Make sure public key matches a hash in DNS
            pkhash = md5(pubkey).digest()
            if pkhash not in self.main.state.dns_pkhashes:
                # Not useful to me, but still forward it
                return

            # Generate RSA object from public key
            try:
                rsa_obj = RSA.construct((bytes_to_long(pubkey), 65537L))
            except:
                return

            # Verify signature
            if not self.verifySignature(
                rsa_obj, data, signature, broadcast=True):
                # Useless...
                raise BadBroadcast

            # Keep track of the timestamp
            osm.bcm.updateBridgeTime(pktnum)

            # Update basic status
            n = osm.refreshNodeStatus(
                src_ipp, None, expire, sesid, uptime, persist, '', '')

            # Update bridge-specific status
            osm.bcm.refreshBridgeNodeStatus(
                n, pktnum, rsa_obj, hashes, do_request=False)

        self.handleBroadcast(ad, data, check_cb, bridgey=True)


    def handlePacket_bY(self, ad, data):
        # Bridge Sync Reply

        osm = self.main.osm
        if not osm:
            raise BadTimingError("Not ready for bridge sync reply")

        (kind, src_ipp, pktnum, expire, sesid, uptime, flags, rest
         ) = self.decodePacket('!2s6sQH4sIB+', data)

        self.checkSource(src_ipp, ad, exempt_ip=True)

        persist = bool(flags & core.PERSIST_BIT)

        (hashes, rest
         ) = self.decodeString1(rest, 16)
        
        hashes = [h for h, in self.decodeChunkList('!16s', hashes)]

        (pubkey, rest
         ) = self.decodeString2(rest)

        c_nbs, rest = self.decodeNodeList(rest)
        u_nbs, rest = self.decodeNodeList(rest)

        signature = rest

        if not (expire <= 30*60):
            raise BadPacketError("Expire time out of range")

        class Skip(Exception):
            pass

        try:
            # If the signed message is too old, discard it.
            if osm.bcm.signatureExpired(pktnum):
                raise Skip

            # If we've received a newer status update, then this is useless.
            try:
                n = osm.lookup_ipp[src_ipp]
            except KeyError:
                pass
            else:
                if self.isOutdatedBridgeStatus(n, pktnum):
                    raise Skip

            # Make sure public key matches a hash in DNS
            pkhash = md5(pubkey).digest()
            if pkhash not in self.main.state.dns_pkhashes:
                raise Skip

            # Generate RSA object from public key
            try:
                rsa_obj = RSA.construct((bytes_to_long(pubkey), 65537L))
            except:
                raise Skip

            # Verify signature
            if not self.verifySignature(
                rsa_obj, data, signature, broadcast=False):
                raise Skip

            # Keep track of the timestamp
            osm.bcm.updateBridgeTime(pktnum)

            # Update basic status
            n = osm.refreshNodeStatus(
                src_ipp, None, expire, sesid, uptime, persist, '', '')

            # Update bridge-specific status
            osm.bcm.refreshBridgeNodeStatus(
                n, pktnum, rsa_obj, hashes, do_request=True)

        except Skip:
            pass

        # Process the sync reply
        if osm.sm:
            osm.sm.receivedSyncReply(src_ipp, c_nbs, u_nbs)


    def handlePacket_BB(self, ad, data):

        osm = self.main.osm

        def check_cb(src_n, src_ipp, rest):

            (pktnum, rest
             ) = self.decodePacket('!Q+', rest)

            (blockdata, rest
             ) = self.decodeString2(rest)

            if rest:
                raise BadPacketError("Extra Data")

            # If the signed message is too old, discard it.
            if osm.bcm.signatureExpired(pktnum):
                raise BadBroadcast

            osm.bcm.handleDataBlock(src_ipp, blockdata)

        self.handleBroadcast(ad, data, check_cb, bridgey=True)


    def handlePacket_BC(self, ad, data):
        osm = self.main.osm

        def check_cb(src_n, src_ipp, rest):

            (pktnum, rest
             ) = self.decodePacket('!Q+', rest)

            (chunks, signature
             ) = self.decodeString2(rest)

            # If the signed message is too old, discard it.
            if osm.bcm.signatureExpired(pktnum):
                raise BadBroadcast

            # If this doesn't look like a bridge node,
            # then just blindly forward it.
            if not (src_n and src_n.bridge_data):
                return None

            bdata = src_n.bridge_data

            # Verify signature
            if not self.verifySignature(
                bdata.rsa_obj, data, signature, broadcast=True):
                return
            
            # Keep track of the timestamp
            osm.bcm.updateBridgeTime(pktnum)

            try:
                bdata.processChunks(chunks, pktnum)
            except ChunkError, e:
                self.main.logPacket("BC chunk error: %s" % str(e))

        self.handleBroadcast(ad, data, check_cb, bridgey=True)


    def handlePacket_BX(self, ad, data):
        osm = self.main.osm

        def check_cb(src_n, src_ipp, rest):

            (pktnum, signature
             ) = self.decodePacket('!Q+', rest)

            # If the signed message is too old, discard it.
            if osm.bcm.signatureExpired(pktnum):
                raise BadBroadcast

            # If we've received a newer status update, then this is useless.
            if self.isOutdatedBridgeStatus(src_n, pktnum):
                raise BadBroadcast

            # If this doesn't look like a bridge node,
            # then just blindly forward it.
            if not (src_n and src_n.bridge_data):
                return None

            bdata = src_n.bridge_data
            
            # Verify signature
            if not self.verifySignature(
                bdata.rsa_obj, data, signature, broadcast=True):
                return

            # Keep track of the timestamp
            osm.bcm.updateBridgeTime(pktnum)

            # Exit the node
            osm.nodeExited(src_n, "Bridge Exit")

        self.handleBroadcast(ad, data, check_cb, bridgey=True)
        

    def handlePacket_bC(self, ad, data):

        (kind, src_ipp, ack_key, dst_nhash, rest
         ) = self.decodePacket('!2s6s8s4s+', data)

        pktnum, = struct.unpack('!Q', ack_key)

        (chunks, signature
         ) = self.decodeString2(rest)

        osm = self.main.osm
        if not (osm and osm.syncd):
            raise BadTimingError("Not ready for bC")

        self.checkSource(src_ipp, ad, exempt_ip=True)

        # If the signed message is too old, discard it.
        if osm.bcm.signatureExpired(pktnum):
            raise BadTimingError("bC: expired signature")

        try:
            bdata = osm.lookup_ipp[src_ipp].bridge_data
            if not bdata:
                raise KeyError
        except KeyError:
            raise BadTimingError("bC: Not found")

        # Verify Signature
        if not self.verifySignature(
            bdata.rsa_obj, data, signature, broadcast=False):
            raise BadPacketError("bC: signature didn't verify")

        # Keep track of the timestamp
        osm.bcm.updateBridgeTime(pktnum)

        bdata.receivedPrivateChunks(pktnum, ack_key, dst_nhash, chunks)


    def handlePacket_bB(self, ad, data):
        # Bridge private data block

        (kind, src_ipp, rest
         ) = self.decodePacket('!2s6s+', data)

        self.checkSource(src_ipp, ad, exempt_ip=True)

        (blockdata, rest
         ) = self.decodeString2(rest)

        if rest:
            raise BadPacketError("Extra data")

        osm = self.main.osm
        if not osm:
            raise BadTimingError("Not ready for bB")

        osm.bcm.handleDataBlock(src_ipp, blockdata)


##############################################################################


class NickNode(object):
    implements(IDtellaNickNode)

    __lt__ = lambda self,other: self.nick <  other.nick
    __le__ = lambda self,other: self.nick <= other.nick

    is_peer = False
    
    def __init__(self, parent_n, nick, info, mode, pktnum):
        self.parent_n = parent_n
        self.nick = nick
        
        self.dcinfo = ""
        self.location = ""
        self.shared = 0
        self.setInfo(info)
        
        self.pktnum = pktnum
        self.mode = mode


    def setInfo(self, info):
        old_dcinfo = self.dcinfo
        self.dcinfo, self.location, self.shared = parse_incoming_info(info)
        return (self.dcinfo != old_dcinfo)


    def setNoUser(self):
        self.setInfo('')


    def event_PrivateMessage(self, main, text, fail_cb):
        osm = main.osm

        if len(text) > 512:
            text = text[:512]

        flags = 0

        ack_key = self.parent_n.getPMAckKey()

        packet = ['bP']
        packet.append(osm.me.ipp)
        packet.append(ack_key)
        packet.append(osm.me.nickHash())
        packet.append(struct.pack('!B', len(self.nick)))
        packet.append(self.nick)
        packet.append(struct.pack('!BH', flags, len(text)))
        packet.append(text)
        packet = ''.join(packet)

        self.parent_n.sendPrivateMessage(main.ph, ack_key, packet, fail_cb)


    def event_ConnectToMe(self, main, port, use_ssl, fail_cb):
        fail_cb("IRC users don't have any files.")


    def event_RevConnectToMe(self, main, fail_cb):
        fail_cb("IRC users don't have any files.")


    def checkRevConnectWindow(self):
        return False

verifyClass(IDtellaNickNode, NickNode)


##############################################################################


class BridgeNodeData(object):

    class Ban(object):
        def __init__(self, ipmask, enable, pktnum):
            self.ipmask = ipmask
            self.enable = enable
            self.pktnum = pktnum


    def __init__(self, main, parent_n):
        self.main = main
        self.parent_n = parent_n
        self.blocks = {}   # {hash: [None | data]}
        self.hashlist = []
        self.status_pktnum = None

        self.topic_flag = False
        
        self.moderated = False

        self.last_assembled_pktnum = None
        self.nicks = {} # {nick: NickNode()}
        self.bans = {}  # {(ip,mask): Ban()}

        # Tuple of info strings; indices match up with the nick modes
        self.infostrings = ()

        self.req_blocks = RandSet()
        self.requestBlocks_dcall = None

        # Register me in BridgeClientManager
        self.main.osm.bcm.bridges.add(self)


    def setHashList(self, hashlist, do_request):
       
        self.hashlist = hashlist
        
        self.blocks = dict.fromkeys(self.hashlist, None)

        bcm = self.main.osm.bcm

        # Start with no requested blocks
        self.req_blocks.clear()

        for bhash in self.blocks:
            try:
                bk = bcm.unclaimed_blocks.pop((self.parent_n.ipp, bhash))
            except KeyError:
                # If we're requesting blocks, then add this to the list
                if do_request:
                    self.req_blocks.add(bhash)
            else:
                bk.expire_dcall.cancel()
                self.blocks[bhash] = bk.data

        self.assembleBlocks()

        # Start requesting blocks (if any)
        self.scheduleRequestBlocks()


    def scheduleRequestBlocks(self):

        # After we receive a sync reply from the bridge, individually
        # request the full data for each block hash.

        dcall_discard(self, 'requestBlocks_dcall')

        if not self.req_blocks:
            return

        def cb(timeout):
            self.requestBlocks_dcall = None

            # Pick one of the hashes randomly
            try:
                bhash = self.req_blocks.peek()
            except KeyError:
                return

            # Build request packet
            packet = ['bQ']
            packet.append(self.main.osm.me.ipp)
            packet.append(bhash)

            # Send to bridge
            ad = Ad().setRawIPPort(self.parent_n.ipp)
            self.main.ph.sendPacket(''.join(packet), ad.getAddrTuple())

            # Too many failures, just give up
            if timeout > 30.0:
                self.req_blocks.clear()
                return

            # Schedule next request.
            # This will become immediate if a reply arrives.
            when = random.uniform(0.9, 1.1) * timeout
            timeout *= 1.2
            self.requestBlocks_dcall = reactor.callLater(when, cb, timeout)

        self.requestBlocks_dcall = reactor.callLater(0, cb, 1.0)


    def addDataBlock(self, bhash, data):
        # Return True if the block was accepted, False otherwise

        if bhash not in self.blocks:
            return False

        # If we're requesting blocks, then mark this one off
        # and possibly ask for more.
        
        if bhash in self.req_blocks:
            self.req_blocks.discard(bhash)
            self.scheduleRequestBlocks()

        # Record the block data, and check if it's time to assemble
        # all the blocks together.

        if self.blocks[bhash] is None:
            self.blocks[bhash] = data
            self.assembleBlocks()

        return True


    def assembleBlocks(self):

        osm = self.main.osm

        # DEBUG
        i=0
        for bk in self.blocks.itervalues():
            if bk is None:
                i+=1

        # Check if all the blocks exist yet
        if None in self.blocks.itervalues():
            return
        
        data = ''.join([self.blocks[bhash] for bhash in self.hashlist])

        self.hashlist = []
        self.blocks = {}

        # This will be toggled back to True if the topic is set
        self.topic_flag = False

        # Default to disabled
        self.moderated = False

        try:
            self.processChunks(data, self.status_pktnum)
        except ChunkError, e:
            self.main.logPacket("Couldn't assemble blocks: %s" % e)

        # Remove any nicks who aren't mentioned in this update
        dead_nicks = []

        for n in self.nicks.values():
            if n.pktnum < self.status_pktnum:
                del self.nicks[n.nick]
                if n.mode != 0xFF:
                    dead_nicks.append(n)

        # Report all the nicks that we deleted
        dead_nicks.sort()
        for n in dead_nicks:
            osm.nkm.removeNode(n, "Dead")

        # Remove any bans which aren't mentioned in this update
        for b in self.bans.values():
            if b.pktnum < self.status_pktnum:
                del self.bans[b.ipmask]

        # If not topic was set, release control of it
        if not self.topic_flag:
            osm.tm.checkLeavingNode(self.parent_n)

        self.last_assembled_pktnum = self.status_pktnum


    def processChunks(self, data, pktnum):

        # Outdated means that this chunk list is older than the chunk
        # list from the last full status update.  Therefore, it only
        # really applies to private bC messages.
        outdated = (
            (self.last_assembled_pktnum is not None)
            and
            (pktnum < self.last_assembled_pktnum)
            )

        osm = self.main.osm

        ptr = 0

        while ptr < len(data):
            if data[ptr] == 'N':
                ptr += 1
                
                try:
                    (mode, nick_len
                     ) = struct.unpack("!BB", data[ptr:ptr+2])
                    ptr += 2

                    nick = data[ptr:ptr+nick_len]
                    ptr += nick_len

                except struct.error:
                    raise ChunkError("N: struct error")
                
                if len(nick) != nick_len:
                    raise ChunkError("N: Nick Length Mismatch")

                if not outdated:
                    self.updateNick(nick, mode, pktnum)

            elif data[ptr] == 'C':
                ptr += 1

                try:
                    (chat_pktnum, flags, nick_len
                     ) = struct.unpack("!IBB", data[ptr:ptr+6])
                    ptr += 6

                    nick = data[ptr:ptr+nick_len]
                    ptr += nick_len

                    (text_len,) = struct.unpack("!H", data[ptr:ptr+2])
                    ptr += 2

                    text = data[ptr:ptr+text_len]
                    ptr += text_len

                except struct.error:
                    raise ChunkError("C: Struct Error")

                if len(nick) != nick_len:
                    raise ChunkError("C: Nick length mismatch")

                if text_len > 1024 or len(text) != text_len:
                    raise ChunkError("C: Text length mismatch")

                if osm.syncd:
                    osm.cms.addMessage(
                        self.parent_n, chat_pktnum, nick, text, flags)

            elif data[ptr] == 'M':
                ptr += 1

                try:
                    (flags, nick_len
                     ) = struct.unpack("!BB", data[ptr:ptr+2])
                    ptr += 2

                    nick = data[ptr:ptr+nick_len]
                    ptr += nick_len

                    (text_len,) = struct.unpack("!H", data[ptr:ptr+2])
                    ptr += 2

                    text = data[ptr:ptr+text_len]
                    ptr += text_len

                except struct.error:
                    raise ChunkError("M: Struct Error")

                if len(nick) != nick_len:
                    raise ChunkError("M: nick length mismatch")

                if text_len > 1024 or len(text) != text_len:
                    raise ChunkError("M: text length mismatch")

                self.handlePrivateMessage(flags, nick, text)

            elif data[ptr] == 'K':
                ptr += 1

                try:
                    (ipp, pktnum, flags, l33t_len
                     ) = struct.unpack("!6sIBB", data[ptr:ptr+12])
                    ptr += 12

                    l33t = data[ptr:ptr+l33t_len]
                    ptr += l33t_len

                    (n00b_len,) = struct.unpack("!B", data[ptr:ptr+1])
                    ptr += 1

                    n00b = data[ptr:ptr+n00b_len]
                    ptr += n00b_len

                    (reason_len,) = struct.unpack("!H", data[ptr:ptr+2])
                    ptr += 2

                    reason = data[ptr:ptr+reason_len]
                    ptr += reason_len

                except struct.error:
                    raise ChunkError("K: Struct error")

                if len(l33t) != l33t_len:
                    raise ChunkError("K: l33t length mismatch")

                if len(n00b) != n00b_len:
                    raise ChunkError("K: n00b length mismatch")

                if reason_len > 1024 or len(reason) != reason_len:
                    raise ChunkError("K: reason length mismatch")

                self.handleKick(ipp, pktnum, flags, l33t, n00b, reason)

            elif data[ptr] == 'B':
                ptr += 1

                try:
                    (subnet, ip
                     ) = struct.unpack("!Bi", data[ptr:ptr+5])
                    ptr += 5

                except struct.error:
                    raise ChunkError("B: struct error")

                enable = bool(subnet & 0x80)
                subnet &= 0x3F

                try:
                    mask = ipv4.CidrNumToMask(subnet)
                except ValueError:
                    raise ChunkError("B: Subnet out of range")

                ipmask = (ip, mask)

                if not outdated:
                    self.updateBan(ipmask, enable, pktnum)

            elif data[ptr] == 'I':
                ptr += 1

                try:
                    (info_len,
                     ) = struct.unpack("!H", data[ptr:ptr+2])
                    ptr += 2

                    info = data[ptr:ptr+info_len]
                    ptr += info_len
                    
                except struct.error:
                    raise ChunkError("I: struct error")

                if len(info) != info_len:
                    raise ChunkError("I: info length mismatch")

                if not outdated:
                    self.handleInfo(info)

            elif data[ptr] == 'T':
                ptr += 1

                try:
                    (flags, nick_len,
                     ) = struct.unpack("!BB", data[ptr:ptr+2])
                    ptr += 2

                    nick = data[ptr:ptr+nick_len]
                    ptr += nick_len

                    (topic_len,) = struct.unpack("!B", data[ptr:ptr+1])
                    ptr += 1

                    topic = data[ptr:ptr+topic_len]
                    ptr += topic_len

                except struct.error:
                    raise ChunkError("T: Struct Error")

                if len(nick) != nick_len:
                    raise ChunkError("T: nick length mismatch")

                if topic_len > 1024 or len(topic) != topic_len:
                    raise ChunkError("T: topic length mismatch")

                changed = bool(flags & core.CHANGE_BIT)

                if not outdated:
                    osm.tm.updateTopic(
                        self.parent_n, nick, topic, changed)

                    self.topic_flag = True

            elif data[ptr] == 'F':
                ptr += 1

                try:
                    (flags,
                     ) = struct.unpack("!B", data[ptr:ptr+1])
                    ptr += 1
                except struct.error:
                    raise ChunkError("F: struct error")

                if not outdated:
                    self.moderated = bool(flags & core.MODERATED_BIT)

            else:
                raise ChunkError("Unknown Chunk '%s'" % data[ptr])


    def receivedPrivateChunks(self, pktnum, ack_key, dst_nhash, chunks):

        osm = self.main.osm

        ack_flags = 0

        try:
            if dst_nhash != osm.me.nickHash():
                raise Reject

            if self.parent_n.pokePMKey(ack_key):
                # Haven't seen this message before, so handle it.

                try:
                    self.processChunks(chunks, pktnum)
                except ChunkError:
                    raise Reject

        except Reject:
            ack_flags |= core.ACK_REJECT_BIT

        self.main.ph.sendAckPacket(
            self.parent_n.ipp, core.ACK_PRIVATE, ack_flags, ack_key)


    def updateNick(self, nick, mode, pktnum):
        osm = self.main.osm

        try:
            if mode == 0xFF:
                raise IndexError
            info = self.infostrings[mode]
        except IndexError:
            info = ''
        
        try:
            n = self.nicks[nick]
        except KeyError:
            # New nick
            n = self.nicks[nick] = NickNode(
                self.parent_n, nick, info, mode, pktnum)

            if mode != 0xFF:
                try:
                    osm.nkm.addNode(n)
                except NickError:
                    # Collision of some sort
                    n.mode = 0xFF
        else:

            # Existing nick
            if pktnum < n.pktnum:
                return

            n.pktnum = pktnum

            if n.mode == mode:
                return

            if mode != 0xFF:

                if n.mode != 0xFF:
                    # Change mode of existing nick
                    osm.nkm.setInfoInList(n, info)
                    
                else:
                    # Dead nick coming back online
                    n.setInfo(info)
                    try:
                        osm.nkm.addNode(n)
                    except NickError:
                        # Collision of some sort
                        mode = 0xFF

            elif n.mode != 0xFF:
                # Remove existing nick
                osm.nkm.removeNode(n, "Going Offline")

            n.mode = mode


    def updateBan(self, ipmask, enable, pktnum):

        osm = self.main.osm

        try:
            b = self.bans[ipmask]
        except KeyError:
            b = self.bans[ipmask] = self.Ban(ipmask, enable, pktnum)
        else:
            # Update packet number, ignore old ones.
            if b.pktnum < pktnum:
                b.pktnum = pktnum
            else:
                return

            # Update state, ignore non-changes.
            if b.enable != enable:
                b.enable = enable
            else:
                return

        osm.banm.scheduleRebuildBans()


    def handlePrivateMessage(self, flags, nick, text):
        
        dch = self.main.getOnlineDCH()
        if dch:
            if flags & core.NOTICE_BIT:
                # Notice sent directly to this user.
                # Display it in the chat window
                dch.pushChatMessage("*N %s" % nick, text)
            else:
                # Can't support /me very well in a private message,
                # so just stick a * at the beginning.
                if flags & core.SLASHME_BIT:
                    text = '* ' + text
                dch.pushPrivMsg(nick, text)


    def handleKick(self, ipp, pktnum, flags, l33t, n00b, reason):
        # Find the node associated with the n00b's ipp
        osm = self.main.osm
        ph = self.main.ph
        me = osm.me

        if ipp == me.ipp:
            n = me
        else:
            try:
                n = osm.lookup_ipp[ipp]
            except KeyError:
                return

        # Check if the user has rejoined by the time we got this
        outdated = ph.isOutdatedStatus(n, pktnum)

        dch = self.main.getOnlineDCH()

        if n is me:
            
            # Make sure I'm online, and this kick isn't old somehow
            if dch and not outdated:

                # If the bridge requested a rejoin, then have the client come
                # back in 5..10 minutes.
                if flags & core.REJOIN_BIT:
                    rejoin_time = random.uniform(60*5, 60*10)
                else:
                    rejoin_time = None

                # Fix pktnum for my next status update.
                me.status_pktnum = pktnum

                # Force the DC client to become invisible.
                lines = [
                    "You were kicked by %s: %s" % (l33t, reason),
                    "Type !REJOIN to get back in."
                ]
                self.main.kickObserver(lines, rejoin_time)

        else:
            # Display text even for outdated messages, because the
            # Updated status message from the kicked node is racing
            # against the kick packet.  Also, if n00b is empty, then
            # treat it as a silent kick.
            if dch and n00b:
                dch.pushStatus("%s has kicked %s: %s" % (l33t, n00b, reason))

            if not outdated:
                # Drop this node from the nick list (if it's there)
                osm.nkm.removeNode(n, "Kicked")
                n.setNoUser()

                # The next valid broadcast should have pktnum+1
                n.status_pktnum = pktnum


    def handleInfo(self, info):
        infostrings = tuple(info.split('|'))

        if self.infostrings == infostrings:
            return

        self.infostrings = infostrings

        osm = self.main.osm

        # Scan through all the nicks, and fill in their info strings

        for n in self.nicks.itervalues():

            if n.mode == 0xFF:
                continue

            try:
                info = infostrings[n.mode]
            except IndexError:
                info = ''

            osm.nkm.setInfoInList(n, info)


    def myNodeExited(self):
        osm = self.main.osm
        
        for n in self.nicks.itervalues():
            osm.nkm.removeNode(n, "Bridge Exited")

        self.nicks.clear()
        self.shutdown()

        # Unregister me from the BridgeClientManager
        osm.bcm.bridges.remove(self)
        osm.banm.scheduleRebuildBans()


    def sendTopicChange(self, topic):
        osm = self.main.osm
        me = osm.me

        topic = topic[:255]

        ack_key = self.parent_n.getPMAckKey()
        
        packet = ['bT']
        packet.append(osm.me.ipp)
        packet.append(ack_key)
        packet.append(me.nickHash())
        packet.append(struct.pack('!B', len(topic)))
        packet.append(topic)
        packet = ''.join(packet)

        def fail_cb(detail):
            dch = self.main.getOnlineDCH()
            if dch:
                if detail == "Rejected":
                    dch.pushStatus("Sorry, the topic has been locked.")
                else:
                    dch.pushStatus("Failed to set topic: Timeout")

        ph = self.main.ph
        self.parent_n.sendPrivateMessage(ph, ack_key, packet, fail_cb)


    def shutdown(self):
        dcall_discard(self, 'requestBlocks_dcall')


###############################################################################
    

class BridgeClientManager(object):

    class UnclaimedBlock(object):

        def __init__(self, data):
            self.data = data
            self.expire_dcall = None


        def scheduleExpire(self, blocks, key):
            # Expire this block if it's not claimed in 15 seconds
            
            if self.expire_dcall:
                self.expire_dcall.reset(15.0)
                return

            def cb(blocks, key):
                del blocks[key]

            self.expire_dcall = reactor.callLater(15.0, cb, blocks, key)


    def __init__(self, main):
        self.main = main

        # Keep track of the latest bridge packet number, so that older
        # signed messages can be discarded.
        self.bridge_time = 0
        self.unclaimed_blocks = {}

        # Every BridgeNodeData gets registered here
        self.bridges = set()


    def isModerated(self):
        for b in self.bridges:
            if b.moderated:
                return True

        return False


    def signatureExpired(self, pktnum):
        # Return True if the given timestamp has expired.

        time = pktnum >> 24
        return (time < self.bridge_time - 60)


    def updateBridgeTime(self, pktnum):
        # Update the stored bridge_time value, if the new value is larger.

        time = pktnum >> 24

        if time > self.bridge_time:
            self.bridge_time = time
        

    def refreshBridgeNodeStatus(self, n, pktnum, rsa_obj, hashes, do_request):

        if n.bridge_data:
            bdata = n.bridge_data
        else:
            bdata = n.bridge_data = BridgeNodeData(self.main, n)

        bdata.status_pktnum = pktnum
        bdata.rsa_obj = rsa_obj
        bdata.setHashList(hashes, do_request)


    def handleDataBlock(self, ipp, data):
        # Call this when a data block arrives from the network

        osm = self.main.osm

        bhash = md5(data).digest()
        key = (ipp, bhash)

        try:
            bdata = osm.lookup_ipp[ipp].bridge_data
            if not bdata:
                raise KeyError
        except KeyError:
            self.addUnclaimedDataBlock(key, data)
        else:
            if not bdata.addDataBlock(bhash, data):
                self.addUnclaimedDataBlock(key, data)


    def addUnclaimedDataBlock(self, key, data):
        # Add a data block to the unclaimed_blocks list, and let it sit
        # there either until it's claimed, or it expires.
        
        try:
            bk = self.unclaimed_blocks[key]
        except KeyError:
            bk = self.unclaimed_blocks[key] = self.UnclaimedBlock(data)

        bk.scheduleExpire(self.unclaimed_blocks, key)


    def shutdown(self):

        # Cancel dcalls
        for bk in self.unclaimed_blocks.values():
            bk.expire_dcall.cancel()

        self.unclaimed_blocks.clear()

