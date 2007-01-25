from twisted.internet import reactor

from dtella import BadTimingError, BadPacketError, BadBroadcast
import dtella

from dtella_util import RandSet, Ad, dcall_discard

from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA
import md5
import struct
import random

class ChunkError(Exception):
    pass

class BridgeClientProtocol(dtella.PeerHandler):

    def verifySignature(self, rsa_obj, data, sig, broadcast):
        # 0:2 = kind
        # 2:8 = neighbor ipp
        # 8:9 = hop limit
        # 9:10 = flags
        # 10:16 = source ipp
        # 16: = "the rest"

        if not rsa_obj:
            print "rsa_obj not defined"
            return False

        # Grab the kind, skip over the header, and get everything up
        # to but not including the signature.
        if broadcast:
            body = data[0:2] + data[10:-len(sig)]
        else:
            body = data[:-len(sig)]

        data_hash = md5.new(body).digest()
        sig_tuple = (bytes_to_long(sig),)

        try:
            return rsa_obj.verify(data_hash, sig_tuple)
        except:
            print "Error verifying signature"
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

            persist = bool(flags & dtella.PERSIST_BIT)

            (hashes, rest
             ) = self.decodeString1(rest, 16)
            
            hashes = [h for h, in self.decodeChunkList('!16s', hashes)]

            (pubkey, signature
             ) = self.decodeString2(rest)

            if expire > 30*60:
                raise BadPacketError("Expire time > 30 minutes")

            # If the signed message is too old, discard it.
            if osm.bcm.signatureExpired(pktnum):
                raise BadBroadcast

            # If we've received a newer status update, then this is useless.
            if self.isOutdatedBridgeStatus(src_n, pktnum):
                raise BadBroadcast

            def new_cb():
                # Make sure public key matches a hash in DNS
                pkhash = md5.new(pubkey).digest()
                if pkhash not in self.main.dnsh.pkhashes:
                    return

                # Generate RSA object from public key
                try:
                    rsa_obj = RSA.construct((bytes_to_long(pubkey), 65537L))
                except:
                    return

                # Verify signature
                if not self.verifySignature(
                    rsa_obj, data, signature, broadcast=True):
                    return

                # Keep track of the timestamp
                osm.bcm.updateBridgeTime(pktnum)

                # Update basic status
                n = osm.refreshNodeStatus(
                    src_ipp, None, expire, sesid, uptime, persist, '', '')

                # Update bridge-specific status
                osm.bcm.refreshBridgeNodeStatus(
                    n, pktnum, rsa_obj, hashes, do_request=False)

            return new_cb

        self.handleBroadcast(ad, data, check_cb)


    def handlePacket_bY(self, ad, data):
        # Bridge Sync Reply

        osm = self.main.osm
        if not osm:
            raise BadTimingError("Not ready for bridge sync reply")

        (kind, src_ipp, pktnum, expire, sesid, uptime, flags, rest
         ) = self.decodePacket('!2s6sQH4sIB+', data)

        self.checkSource(src_ipp, ad)

        persist = bool(flags & dtella.PERSIST_BIT)

        (hashes, rest
         ) = self.decodeString1(rest, 16)
        
        hashes = [h for h, in self.decodeChunkList('!16s', hashes)]

        (pubkey, rest
         ) = self.decodeString2(rest)

        c_nbs, rest = self.decodeNodeList(rest)
        u_nbs, rest = self.decodeNodeList(rest)

        signature = rest

        if expire > 30*60:
            raise BadPacketError("Expire time > 30 minutes")

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
            pkhash = md5.new(pubkey).digest()
            if pkhash not in self.main.dnsh.pkhashes:
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

            def new_cb():
                osm.bcm.handleDataBlock(src_ipp, blockdata)

            return new_cb

        self.handleBroadcast(ad, data, check_cb)


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

            def new_cb():
                bdata = src_n.bridge_data

                # Verify signature
                if not self.verifySignature(
                    bdata.rsa_obj, data, signature, broadcast=True):
                    print "BC: Invalid signature"
                    return

                # Keep track of the timestamp
                osm.bcm.updateBridgeTime(pktnum)

                try:
                    bdata.processChunks(chunks, pktnum)
                except ChunkError:
                    print "BC: bad chunks"

            return new_cb

        self.handleBroadcast(ad, data, check_cb)


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

            def new_cb():
                bdata = src_n.bridge_data
                
                # Verify signature
                if not self.verifySignature(
                    bdata.rsa_obj, data, signature, broadcast=True):
                    print "BX: Invalid signature"
                    return

                # Keep track of the timestamp
                osm.bcm.updateBridgeTime(pktnum)

                # Exit the node
                osm.nodeExited(src_n)

            return new_cb

        self.handleBroadcast(ad, data, check_cb)
        

    def handlePacket_bC(self, ad, data):

        (kind, src_ipp, ack_key, dst_nhash, rest
         ) = self.decodePacket('!2s6s8s4s+', data)

        pktnum, = struct.unpack('!Q', ack_key)

        (chunks, signature
         ) = self.decodeString2(rest)

        osm = self.main.osm
        if not (osm and osm.syncd):
            raise BadTimingError("Not ready for bC")

        self.checkSource(src_ipp, ad)

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
            print "bC: Invalid signature"
            return

        # Keep track of the timestamp
        osm.bcm.updateBridgeTime(pktnum)

        bdata.receivedPrivateChunks(pktnum, ack_key, dst_nhash, chunks)


    def handlePacket_bB(self, ad, data):
        # Bridge private data block

        (kind, src_ipp, rest
         ) = self.decodePacket('!2s6s+', data)

        self.checkSource(src_ipp, ad)

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

    __lt__ = lambda self,other: self.nick <  other.nick
    __le__ = lambda self,other: self.nick <= other.nick
    
    def __init__(self, parent_n, nick, info, mode, pktnum):
        self.parent_n = parent_n
        self.nick = nick
        self.info = info
        self.pktnum = pktnum
        self.mode = mode


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

        osm.pmm.sendMessage(self.parent_n, ack_key, packet, fail_cb)


    def event_ConnectToMe(self, main, port, fail_cb):
        fail_cb()


    def event_RevConnectToMe(self, main, fail_cb):
        fail_cb()            


##############################################################################


class BridgeNodeData(object):

    def __init__(self, main, parent_n):
        self.main = main
        self.parent_n = parent_n
        self.blocks = {}   # {hash: [None | data]}
        self.hashlist = []
        self.status_pktnum = None

        self.last_assembled_pktnum = None
        self.nicks = {} # {nick: NickNode()}

        # Tuple of info strings; indices match up with the nick modes
        self.infostrings = ()

        # Received Private Messages (Bc messages)
        self.msgs = {}

        self.req_blocks = RandSet()
        self.requestBlocks_dcall = None


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

        if not self.req_blocks:
            dcall_discard(self, 'requestBlocks_dcall')
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

        # DEBUG
        i=0
        for bk in self.blocks.itervalues():
            if bk is None:
                i+=1

        print "Need %d more blocks" % i

        # Check if all the blocks exist yet
        if None in self.blocks.itervalues():
            return
        
        data = ''.join([self.blocks[bhash] for bhash in self.hashlist])

        self.hashlist = []
        self.blocks = {}

        try:
            self.processChunks(data, self.status_pktnum)
        except ChunkError:
            print "processChunks FAILED"
            return

        # Remove any nicks who aren't mentioned in this update
        dead_nicks = []

        for n in self.nicks.values():
            if n.pktnum < self.status_pktnum:
                del self.nicks[n.nick]
                if n.mode != 0xFF:
                    dead_nicks.append(n)

        dead_nicks.sort()

        for n in dead_nicks:
            print "Dead nick: '%s'" % n.nick
            osm = self.main.osm
            osm.nkm.removeNode(n)

        self.last_assembled_pktnum = self.status_pktnum


    def processChunks(self, data, pktnum):

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
                        self.parent_n.ipp, chat_pktnum, nick, text, flags)

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
                    (ip, subnet
                     ) = struct.unpack("!4sB", data[ptr:ptr+5])
                    ptr += 5

                except struct.error:
                    raise ChunkError("B: struct error")

                # TODO: handle

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

                self.handleInfo(info)


            elif data[ptr] == 'R':
                ptr += 1

                # TODO: handle

            else:
                raise ChunkError("Unknown Chunk '%s'" % data[ptr])


    def receivedPrivateChunks(self, pktnum, ack_key, dst_nhash, chunks):

        osm = self.main.osm

        ack_flags = 0

        try:
            if dst_nhash != osm.me.nickHash():
                raise dtella.Reject

            if ack_key not in self.msgs:
                # Haven't seen this message before, so handle it.

                try:
                    self.processChunks(chunks, pktnum)
                except ChunkError:
                    raise dtella.Reject

            # Forget about this message in a minute
            try:
                self.msgs[ack_key].reset(60.0)
            except KeyError:
                def cb():
                    self.msgs.pop(ack_key)
                self.msgs[ack_key] = reactor.callLater(60.0, cb)

        except dtella.Reject:
            ack_flags |= dtella.ACK_REJECT_BIT

        self.main.ph.sendAckPacket(
            self.parent_n.ipp, dtella.ACK_PRIVATE, ack_flags, ack_key)


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
                if not osm.nkm.addNode(n):
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
                    osm.nkm.setNodeInfo(n, info)
                    
                else:
                    # Dead nick coming back online
                    n.info = info
                    if not osm.nkm.addNode(n):
                        # Collision of some sort
                        mode = 0xFF

            elif n.mode != 0xFF:
                # Remove existing nick
                osm.nkm.removeNode(n)

            n.mode = mode


    def handlePrivateMessage(self, flags, nick, text):
        
        dch = self.main.getOnlineDCH()
        if dch:
            if flags & dtella.NOTICE_BIT:
                # Notice sent directly to this user.
                # Display it in the chat window
                dch.pushChatMessage("*N %s" % nick, text)
            else:
                # Can't support /me very well in a private message,
                # so just stick a * at the beginning.
                if flags & dtella.SLASHME_BIT:
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
                print "handleKick: can't find node"
                return

        # Check if the user has rejoined by the time we got this
        outdated = ph.isOutdatedStatus(n, pktnum)

        dch = self.main.getOnlineDCH()

        if n is me:
            
            # Make sure I'm online, and this kick isn't old somehow
            if dch and not outdated:

                # Yell at user and make them invisible
                dch.kickMe(l33t, reason)

                # Broadcast an update so nodes who aren't bridge-aware
                # will also see us disappear.
                me.status_pktnum = pktnum
                osm.updateMyInfo()

        else:
            # Display text even for outdated messages, because the
            # Updated status message from the kicked node is racing
            # against the kick packet.
            if dch:
                dch.pushStatus("%s has kicked %s: %s" % (l33t, n00b, reason))

            if not outdated:
                # Drop this node from the nick list (if it's there)
                osm.nkm.removeNode(n)
                n.nick = n.info = ''

                # The next valid broadcast should have pktnum+1
                n.status_pktnum = pktnum


    def handleInfo(self, info):
        infostrings = tuple(info.split('|'))

        print "infostrings=", infostrings

        if self.infostrings == infostrings:
            return

        self.infostrings = infostrings

        osm = self.main.osm

        # Scan through all the nicks, and fill in their info strings

        for n in self.nicks.itervalues():

            if n.mode == 0xFF:
                continue

            try:
                new_info = infostrings[n.mode]
            except IndexError:
                continue

            osm.nkm.setNodeInfo(n, new_info)


    def nodeExited(self):
        osm = self.main.osm
        
        for n in self.nicks.itervalues():
            osm.nkm.removeNode(n)

        self.nicks.clear()
        self.shutdown()


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

            def cb(blocks, key):
                del blocks[key]

            self.expire_dcall = reactor.callLater(15.0, cb, blocks, key)    


    def __init__(self, main):
        self.main = main

        # Keep track of the latest bridge packet number, so that older
        # signed messages can be discarded.
        self.bridge_time = 0
        
        self.unclaimed_blocks = {}


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

        print "refreshBNS: pktnum=%d hashes=%s" % (pktnum, hashes)

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

        bhash = md5.new(data).digest()
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

