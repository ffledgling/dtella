#!/usr/bin/env python
#
#IRC Bridge Test Code
#NOTE: This is only designed to work with UnrealIRCd
#

import fixtwistedtime

from twisted.internet.protocol import ReconnectingClientFactory
from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet import reactor, defer
from twisted.python.runtime import seconds

from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA

import time
import struct
import md5
import random

import dtella
import dtella_state
import dtella_crypto
import dtella_local
from dtella_util import Ad, dcall_discard, dcall_timeleft, validateNick


import dtella_bridge_config as cfg


escape_chars = """!"#%&'()*+,./:;=?@`~"""
base36_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

mode_info = [
    "[~] owner$ $IRC\x01$$0$",
    "[&] super-op$ $IRC\x01$$0$",
    "[@] op$ $IRC\x01$$0$",
    "[%] half-op$ $IRC\x01$$0$",
    "[+] voice$ $IRC\x01$$0$",
    "[_]$ $IRC\x01$$0$",
    "[>] virtual$ $IRC\x01$$0$"
    ]

chan_umodes = 'qaohv'


def base_convert(chars, from_digits, to_digits, min_len=1):
    # Convert chars from one base to another.
    # raises ValueError on invalid input

    total = 0
    for c in chars:
        total = (total * len(from_digits)) + from_digits.index(c)

    out = ''
    while total or len(out) < min_len:
        out = to_digits[total % len(to_digits)] + out
        total //= len(to_digits)

    return out


def dc_to_irc(dnick):
    # Encode a DC nick, for use in IRC.

    if validateNick(dnick):
        raise ValueError

    escapes = ''
    inick = cfg.dc_to_irc_prefix

    for c in dnick:
        if c in escape_chars:
            inick += '`'
            escapes += c
        else:
            inick += c

    if escapes:
        inick += '-' + base_convert(escapes, escape_chars, base36_chars)

    # TODO: Check length?
    
    return inick


def dc_from_irc(inick):
    # Decode an IRC-encoded DC nick, for use in Dtella.

    # Verify prefix
    if len(inick) <= 1 or inick[0] != cfg.dc_to_irc_prefix:
        raise ValueError

    dnick = inick[1:]

    n_escapes = 0
    for c in dnick:
        if c == '`':
            n_escapes += 1

    if n_escapes:
        head, tail = dnick.rsplit('-', 1)
        escapes = base_convert(tail, base36_chars, escape_chars, n_escapes)

        if len(escapes) != n_escapes:
            raise ValueError

        dnick = ''
        n_escapes = 0
        for c in head:
            if c == '`':
                dnick += escapes[n_escapes]
                n_escapes += 1
            else:
                dnick += c

    return dnick


def irc_to_dc(inick):
    # Encode an IRC nick, for use in Dtella
    
    return cfg.irc_to_dc_prefix + inick.replace('|','!')


def irc_from_dc(dnick):
    # Decode a Dtella-encoded IRC nick, for use in IRC.
    if len(dnick) <= 1 or dnick[0] != cfg.irc_to_dc_prefix:
        raise ValueError

    # TODO: Verify that IRC nick contains only sane characters

    return dnick[1:].replace('!','|')


class IRCBadMessage(Exception):
    pass


class IRCServer(LineOnlyReceiver):
    showirc = True

    def __init__(self, main):
        self.data = IRCServerData(self)
        self.main = main
        self.syncd = False
        self.readytosend = False
        self.shutdown_deferred = None

        self.ping_dcall = None
        self.ping_waiting = False


    def connectionMade(self):
        self.main.addIRCServer(self)
        self.sendLine("PASS :%s" % (cfg.irc_password,))
        self.sendLine("SERVER %s 1 :%s" % (cfg.my_host, cfg.my_name))


    def sendLine(self, line):
        line = line.replace('\r', '').replace('\n', '')
        print "<:", line
        LineOnlyReceiver.sendLine(self, line)


    def lineReceived(self, line):

        
        # TOPIC #dtella darkhorse 1161628983 :Dtella :: Development Stage
        # :Paul TOPIC #dtella Paul 1169420711 :Dtella :: Development Stage

        osm = self.main.osm
        
        prefix, command, args = self.parsemsg(line)

        # TOOD: eventually convert this if-chain into a series of functions

        if self.showirc:
            pass
            #print ">:", repr(prefix), repr(command), repr(args)
            print ">:", line

        if command == "PING":
            print "PING? PONG!"
            if len(args) == 1:
                self.sendLine("PONG %s :%s" % (cfg.my_host, args[0]))
            elif len(args) == 2:
                self.sendLine("PONG %s :%s" % (args[1], args[0]))

        elif command == "PONG":
            if self.ping_waiting:
                self.ping_waiting = False
                self.schedulePing()

        elif command == "NICK":

            if args[0][:1] == cfg.irc_to_dc_prefix:
                self.sendLine(
                    ":%s KILL %s :%s (nick reserved for Dtella)"
                    % (cfg.my_host, args[0], cfg.my_host))
                return
                
            if prefix:
                self.data.changeNick(prefix, args[0])
            else:
                self.data.addNick(args[0])

        elif command == "JOIN":
            chans = args[0].split(',')
            self.data.gotJoin(prefix, chans)

        elif command == "PART":
            chans = args[0].split(',')
            self.data.gotPart(prefix, chans)

        elif command == "QUIT":
            self.data.gotQuit(prefix)

        elif command == "KICK":
            chan = args[0]
            l33t = prefix
            n00b = args[1]
            reason = args[2]
            
            self.data.gotKick(chan, l33t, n00b, reason)

        elif command == "KILL":
            # :darkhorse KILL }darkhorse :dhirc.com!darkhorse (TEST!!!)
            # TODO: 'chan' should be removed, since KILL is global.
            chan = cfg.irc_chan
            l33t = prefix
            n00b = args[0]
            reason = args[1]
            
            self.data.gotKick(chan, l33t, n00b, reason)
            self.data.gotQuit(n00b)
        
        elif command == "TOPIC":
            # :Paul TOPIC #dtella Paul 1169420711 :Dtella :: Development Stage
            chan = args[0]
            whoset = args[1]
            text = args[-1]
            self.data.gotTopic(chan, whoset, text)

        elif command == "MODE":
            # :Paul MODE #dtella +vv aaahhh Big_Guy
            whoset = prefix
            chan = args[0]
            change = args[1]
            nicks = args[2:]
            if chan[:1] == '#':
                self.data.gotChanModes(whoset, chan, change, nicks)

        elif command == "SERVER":
            # If we receive this, our password was accepted, so broadcast
            # the Dtella state information if it's available and we haven't
            # sent it already.

            self.sendLine(
                ":%s TKL + Q * %s* bridge.dtella.net 0 %d :Reserved for Dtella"
                % (cfg.my_host, cfg.dc_to_irc_prefix, time.time())
                )

            if not self.readytosend:
                self.readytosend = True

                # Tell the ReconnectingClientFactory that we're cool
                self.factory.resetDelay()

                # Send my own bridge nick
                self.pushFullJoin(cfg.dc_to_irc_bot, "bridge", "dtella.net")

                # Maybe send Dtella nicks
                if self.main.osm and self.main.osm.syncd:
                    self.sendState()
            

        elif command == "EOS" and prefix == cfg.irc_server:
            print "SYNCD!!!!"

            self.showirc = True

            # If we enter the syncd state, send status to Dtella, if Dtella
            # is ready.  Otherwise, Dtella will send its own state when it
            # becomes ready.

            if not self.syncd:
                self.syncd = True
                
                osm = self.main.osm
                if osm and osm.syncd:
                    osm.bsm.sendState()

                self.schedulePing()


        elif command == "PRIVMSG":
            osm = self.main.osm
            if (self.syncd and osm and osm.syncd):

                target = args[0]
                text = args[1]
                flags = 0
                
                if (text[:8], text[-1:]) == ('\001ACTION ', '\001'):
                    text = text[8:-1]
                    flags |= dtella.SLASHME_BIT

                if target == cfg.irc_chan:
                    chunks = []
                    osm.bsm.addChatChunk(
                        chunks, irc_to_dc(prefix), text, flags)
                    osm.bsm.sendBridgeChange(chunks)

                else:
                    try:
                        nick = dc_from_irc(target)
                        n = osm.nkm.lookupNick(nick)
                    except (ValueError, KeyError):
                        return

                    chunks = []
                    osm.bsm.addMessageChunk(
                        chunks, irc_to_dc(prefix), text, flags)
                    osm.bsm.sendPrivateBridgeChange(n, chunks)


        elif command == "NOTICE":
            osm = self.main.osm
            if (self.syncd and osm and osm.syncd):

                target = args[0]
                text = args[1]
                flags = dtella.NOTICE_BIT

                if target == cfg.irc_chan:
                    chunks = []
                    osm.bsm.addChatChunk(
                        chunks, irc_to_dc(prefix), text, flags)
                    osm.bsm.sendBridgeChange(chunks)

                else:
                    try:
                        nick = dc_from_irc(target)
                        n = osm.nkm.lookupNick(nick)
                    except (ValueError, KeyError):
                        return

                    chunks = []
                    osm.bsm.addMessageChunk(
                        chunks, irc_to_dc(prefix), text, flags)
                    osm.bsm.sendPrivateBridgeChange(n, chunks)
                

    def parsemsg(self, s):
        #this breaks up messages received from the other server into their three components:
        # prefix, command, and args
        prefix = ''
        trailing = []
        if not s:
            raise IRCBadMessage("Empty line.")
        if s[0] == ':':
            prefix, s = s[1:].split(' ', 1)
        if s.find(' :') != -1:
            s, trailing = s.split(' :', 1)
            args = s.split()
            args.append(trailing)
        else:
            args = s.split()
        command = args.pop(0)
        return prefix, command, args


    def sendState(self):
        osm = self.main.osm
        assert (self.readytosend and osm and osm.syncd)

        print "Sending Dtella state to IRC..."

        nicks = [(n.nick, n.ipp) for n in osm.nkm.nickmap.values()]
        nicks.sort()

        for nick,ipp in nicks:
            nick = dc_to_irc(nick)
            host = Ad().setRawIPPort(ipp).getTextIP()
            self.pushFullJoin(nick, "dtnode", host)
                

    def pushFullJoin(self, nick, user, host):
        self.sendLine("NICK %s 0 %d %s %s %s 1 :Dtella Peer" %
            (nick, time.time(), user, host, cfg.my_host))
        self.sendLine(":%s JOIN %s" % (nick, cfg.irc_chan))
        

    def pushQuit(self, nick, reason=""):
        self.sendLine(":%s QUIT :%s" % (nick, reason))
        

    def pushPrivMsg(self, nick, text, target=None, action=False):
        if target is None:
            target = cfg.irc_chan
            
        if action:
            text = "\001ACTION %s\001" % text
        
        self.sendLine(":%s PRIVMSG %s :%s" % (nick, target, text))
    

    def pushNotice(self, nick, text, target=None):
        if target is None:
            target = cfg.irc_chan
        self.sendLine(":%s NOTICE %s :%s" % (nick, target, text))


    def schedulePing(self):

        if self.ping_dcall:
            self.ping_dcall.reset(60.0)
            return
        
        def cb():
            print "PING cb():", time.time()
            self.ping_dcall = None

            if self.ping_waiting:
                print "Ping timeout!"
                self.transport.loseConnection()
            else:
                self.sendLine("PING :%s" % cfg.my_host)
                self.ping_waiting = True
                self.ping_dcall = reactor.callLater(15.0, cb)

        self.ping_dcall = reactor.callLater(60.0, cb)


    def event_AddNick(self, nick, n):
        nick = dc_to_irc(nick)
        host = Ad().setRawIPPort(n.ipp).getTextIP()
        self.pushFullJoin(nick, "dtnode", host)

        # Send welcome message
        osm = self.main.osm
        chunks = []
        flags = dtella.NOTICE_BIT
        text = ("The topic for %s is \"%s\""
                % (cfg.irc_chan, self.data.getTopic(cfg.irc_chan))
                )

        osm.bsm.addMessageChunk(
            chunks, cfg.irc_to_dc_bot, text, flags)
        osm.bsm.sendPrivateBridgeChange(n, chunks)


    def event_RemoveNick(self, nick, reason):
        inick = dc_to_irc(nick)
        self.pushQuit(inick, reason)


    def event_UpdateInfo(self, nick, info):
        pass


    def event_ChatMessage(self, nick, text, flags):
        inick = dc_to_irc(nick)

        if flags & dtella.NOTICE_BIT:
            self.pushNotice(inick, text)
        elif flags & dtella.SLASHME_BIT:
            self.pushPrivMsg(inick, text, action=True)
        else:
            self.pushPrivMsg(inick, text)


    def shutdown(self):
        if not self.shutdown_deferred:

            # Remove nick ban
            self.sendLine(
                ":%s TKL - Q * %s* bridge.dtella.net"
                % (cfg.my_host, cfg.dc_to_irc_prefix)
                )

            # Scream
            self.pushQuit(cfg.dc_to_irc_bot, "AIEEEEEEE!")

            # Send SQUIT for completeness
            self.sendLine(":%s SQUIT %s :Bridge Shutting Down"
                          % (cfg.my_host, cfg.my_host))

            # Close connection
            self.transport.loseConnection()

            # This will complete after loseConnection fires
            self.shutdown_deferred = defer.Deferred()

        return self.shutdown_deferred


    def connectionLost(self, result):
        self.main.removeIRCServer(self)
        
        if self.shutdown_deferred:
            self.shutdown_deferred.callback("Bye!")

       
        
##############################################################################


class IRCServerData(object):
    # All users on the IRC network

    class User(object):
        def __init__(self, nick):
            self.nick = nick
            self.chans = set()

    class Channel(object):
        def __init__(self, chan):
            self.chan = chan
            self.users = {}  # nick -> [mode list]
            self.topic = None
            self.topic_who = None

        def getInfoIndex(self, nick):
            # Get the Dtella info index for this user
            try:
                modelist = self.users[nick]
            except KeyError:
                 # virtual
                return 6
            try:
                # qaohv
                return modelist.index(True)
            except ValueError:
                # plain user
                return 5


    def __init__(self, ircs):
        self.ulist = {}
        self.clist = {}
        self.ircs = ircs


    def addNick(self, nick):
        self.ulist[nick] = self.User(nick)


    def changeNick(self, oldnick, newnick):
        try:
            u = self.ulist.pop(oldnick)
        except KeyError:
            print "Nick doesn't exist"
            return

        if newnick in self.ulist:
            print "New nick already exists!"
            return

        u.nick = newnick
        self.ulist[newnick] = u

        for chan in u.chans:
            c = self.getChan(chan)
            c.users[newnick] = c.users.pop(oldnick)

        if cfg.irc_chan in u.chans:

            osm = self.ircs.main.osm
            if (self.ircs.syncd and osm and osm.syncd):

                infoindex = self.getChan(cfg.irc_chan).getInfoIndex(newnick)
                
                chunks = []
                osm.bsm.addChatChunk(
                    chunks, cfg.irc_to_dc_bot,
                    "%s is now known as %s" % (irc_to_dc(oldnick),
                                               irc_to_dc(newnick))
                    )
                osm.bsm.addNickChunk(
                    chunks, irc_to_dc(oldnick), 0xFF)
                osm.bsm.addNickChunk(
                    chunks, irc_to_dc(newnick), infoindex)
                osm.bsm.sendBridgeChange(chunks)


    def gotKick(self, chan, l33t, n00b, reason):

        if chan == cfg.irc_chan:
            osm = self.ircs.main.osm
            if (self.ircs.syncd and osm and osm.syncd):

                try:
                    nick = dc_from_irc(n00b)
                    n = osm.nkm.lookupNick(nick)
                except (ValueError, KeyError):
                    # IRC nick
                    chunks = []
                    osm.bsm.addChatChunk(
                        chunks, cfg.irc_to_dc_bot,
                        "%s has kicked %s: %s" %
                        (irc_to_dc(l33t), irc_to_dc(n00b), reason)
                        )
                    osm.bsm.addNickChunk(chunks, irc_to_dc(n00b), 0xFF)
                    osm.bsm.sendBridgeChange(chunks)
                    
                else:
                    # DC Nick
                    chunks = []
                    osm.bsm.addKickChunk(
                        chunks, n, irc_to_dc(l33t), reason
                        )
                    osm.bsm.sendBridgeChange(chunks)

                    # Forget this nick
                    osm.nkm.removeNode(n)
                    n.nick = n.info = ''

        try:
            u = self.ulist[n00b]
        except KeyError:
            print "Nick doesn't exist"
            return

        c = self.getChan(chan)
        del c.users[n00b]
        u.chans.remove(chan)


    def getChan(self, chan):
        try:
            c = self.clist[chan]
        except KeyError:
            c = self.clist[chan] = self.Channel(chan)
        return c


    def getTopic(self, chan):
        try:
            c = self.clist[chan]
        except KeyError:
            return ""
        
        if c.topic:
            return c.topic

        return ""


    def gotJoin(self, nick, chans):
        try:
            u = self.ulist[nick]
        except KeyError:
            print "nick %s doesn't exist!" % (nick,)
            return

        chans = set(chans) - u.chans

        for chan in chans:
            c = self.getChan(chan)
            c.users[nick] = [False] * len(chan_umodes)
            u.chans.add(chan)

        if cfg.irc_chan in chans:
            osm = self.ircs.main.osm
            if (self.ircs.syncd and osm and osm.syncd):

                infoindex = self.getChan(cfg.irc_chan).getInfoIndex(nick)
                
                chunks = []
                osm.bsm.addNickChunk(
                    chunks, irc_to_dc(nick), infoindex)
                osm.bsm.sendBridgeChange(chunks)


    def gotChanModes(self, whoset, chan, change, nicks):

        val = True
        i = 0

        osm = self.ircs.main.osm
        ch = self.getChan(chan)

        chunks = []

        for c in change:
            if c == '+':
                val = True
            elif c == '-':
                val = False
            elif c == 't':
                # TODO: Topic lock stuff
                pass
            elif c == 'k':
                # Skip over channel key
                i += 1
            elif c == 'l':
                # Skip over channel user limit
                i += 1
            else:
                try:
                    # Check if this is a user mode
                    modeidx = chan_umodes.index(c)
                except ValueError:
                    # Skip unknown modes
                    continue

                # Grab affected nick
                nick = nicks[i]
                i += 1

                # Skip phantom nicks (i.e. nicks on THIS server)
                if nick not in self.ulist:
                    continue

                if chan != cfg.irc_chan:
                    ch.users[nick][modeidx] = val
                    continue

                old_infoindex = ch.getInfoIndex(nick)
                ch.users[nick][modeidx] = val
                new_infoindex = ch.getInfoIndex(nick)

                if new_infoindex == old_infoindex:
                    continue

                if (self.ircs.syncd and osm and osm.syncd):
                    osm.bsm.addNickChunk(
                        chunks, irc_to_dc(nick), new_infoindex)

        if chunks:
            if whoset:
                # Might want to make this formatted better
                text = ' '.join([change]+nicks)

                osm.bsm.addChatChunk(
                    chunks, cfg.irc_to_dc_bot,
                    "%s set mode: %s" % 
                    (irc_to_dc(whoset), text)
                    )

            osm.bsm.sendBridgeChange(chunks)


    def gotQuit(self, nick):
        try:
            u = self.ulist[nick]
        except KeyError:
            print "nick %s doesn't exist!" % (nick,)
            return None

        for chan in u.chans:
            c = self.getChan(chan)
            del c.users[nick]

        if cfg.irc_chan in u.chans:
            osm = self.ircs.main.osm
            if (self.ircs.syncd and osm and osm.syncd):
                chunks = []
                osm.bsm.addNickChunk(chunks, irc_to_dc(nick), 0xFF)
                osm.bsm.sendBridgeChange(chunks)


    def gotPart(self, nick, chans):
        try:
            u = self.ulist[nick]
        except KeyError:
            print "nick %s doesn't exist!" % (nick,)
            return None

        for chan in chans:
            c = self.getChan(chan)
            del c.users[nick]
            u.chans.remove(chan)

        if cfg.irc_chan in chans:
            osm = self.ircs.main.osm
            if (self.ircs.syncd and osm and osm.syncd):
                chunks = []
                osm.bsm.addNickChunk(chunks, irc_to_dc(nick), 0xFF)
                osm.bsm.sendBridgeChange(chunks)


    def gotTopic(self, chan, whoset, text):
        c = self.getChan(chan)
        c.topic = text
        c.topic_who = whoset

        if chan == cfg.irc_chan:
            osm = self.ircs.main.osm
            if (self.ircs.syncd and osm and osm.syncd):
                chunks = []
                osm.bsm.addChatChunk(
                    chunks, cfg.irc_to_dc_bot,
                    "%s changed the topic to \"%s\"" %
                    (irc_to_dc(whoset), text)
                    )
                osm.bsm.sendBridgeChange(chunks)


    def getNicksInChan(self, chan):
        nicks = list(self.getChan(chan).users)
        nicks.sort()
        return nicks


##############################################################################


class IRCFactory(ReconnectingClientFactory):

    initialDelay = 10
    maxDelay = 60*20
    factor = 1.5
    
    def __init__(self, main):
        self.main = main

    def buildProtocol(self, addr):
        p = IRCServer(self.main)
        p.factory = self
        return p


##############################################################################


class BridgeServerProtocol(dtella.PeerHandler):

    def handlePacket_bP(self, ad, data):
        # Private message to IRC nick

        (kind, src_ipp, ack_key, src_nhash, rest
         ) = self.decodePacket('!2s6s8s4s+', data)

        self.checkSource(src_ipp, ad)

        (dst_nick, rest
         ) = self.decodeString1(rest)

        (flags, rest
         ) = self.decodePacket('!B+', rest)

        (text, rest
         ) = self.decodeString2(rest)

        if rest:
            raise BadPacketError("Extra data")

        osm = self.main.osm
        if not (osm and osm.syncd):
            raise BadTimingError("Not ready for PM")

        osm.bsm.receivedPrivateMessage(src_ipp, ack_key, src_nhash,
                                       dst_nick, text)


    def handlePacket_bQ(self, ad, data):
        # Requesting a full data block

        (kind, src_ipp, bhash
         ) = self.decodePacket('!2s6s16s', data)

        self.checkSource(src_ipp, ad)

        osm = self.main.osm
        if not (osm and osm.syncd):
            raise BadTimingError("Not ready for Bq")

        osm.bsm.receivedBlockRequest(src_ipp, bhash)


##############################################################################


class BridgeServerManager(object):

    class CachedBlock(object):
        
        def __init__(self, data):
            self.data = data
            self.expire_dcall = None

        def scheduleExpire(self, blks, key):
            if self.expire_dcall:
                self.expire_dcall.reset(60.0)
                return

            def cb(blks, key):
                del blks[key]

            self.expire_dcall = reactor.callLater(60.0, cb, blks, key)


    def __init__(self, main):
        self.main = main
        self.rsa_obj = RSA.construct(cfg.private_key)

        # 64-bit value, stored as [8-bit pad] [32-bit time] [24-bit counter]
        self.bridge_pktnum = 0

        self.sendState_dcall = None

        self.cached_blocks = {}  # hash -> CachedBlock()


    def nextPktNum(self):

        t = long(time.time())

        if self.bridge_pktnum >> 24 == t:
            self.bridge_pktnum += 1
            print "nextPktNum: Incrementing"
        else:
            self.bridge_pktnum = (t << 24L)
            print "nextPktNum: New Time"

        return struct.pack("!Q", self.bridge_pktnum)


    def syncComplete(self):
        # This is called from OnlineStateManager after the Dtella network
        # is fully syncd.
        osm = self.main.osm

        # Splice in some handlers
        osm.yqrm.sendSyncReply = self.sendSyncReply
        osm.makeExitPacket = self.makeExitPacket

        ircs = self.main.ircs

        # If the IRC server is ready to receive our state, then send it.
        if ircs and ircs.readytosend:
            ircs.sendState()

        # Broadcast the bridge state into Dtella.
        # (This may have no IRC nicks if ircs isn't sycnd yet)
        osm.bsm.sendState()


    def signPacket(self, packet, broadcast):

        import time

        data = ''.join(packet)

        if broadcast:
            body = data[0:2] + data[10:]
        else:
            body = data

        data_hash = md5.new(body).digest()
        
        t = time.time()
        sig, = self.rsa_obj.sign(data_hash, None)
        print "Sign Time=", (time.time() - t)

        packet.append(long_to_bytes(sig))


    def sendSyncReply(self, src_ipp, cont, uncont):
        # This gets spliced into the SyncRequestRoutingManager

        ad = Ad().setRawIPPort(src_ipp)
        osm = self.main.osm

        # Build Packet
        packet = ['bY']

        # My IP:Port
        packet.append(osm.me.ipp)

        # seqnum, expire time, session id, uptime, flags, hashes, pubkey
        block_hashes, blocks = self.getStateData(packet)

        # Contacted Nodes
        packet.append(struct.pack('!B', len(cont)))
        packet.extend(cont)

        # Uncontacted Nodes
        packet.append(struct.pack('!B', len(uncont)))
        packet.extend(uncont)

        # Signature
        self.signPacket(packet, broadcast=False)

        # Send it
        self.main.ph.sendPacket(''.join(packet), ad.getAddrTuple())

        # Keep track of the data for a while,
        # so the node can request it.
        for bhash, data in zip(block_hashes, blocks):
            try:
                b = self.cached_blocks[bhash]
            except KeyError:
                b = self.cached_blocks[bhash] = self.CachedBlock(data)
            b.scheduleExpire(self.cached_blocks, bhash)


    def makeExitPacket(self):
        osm = self.main.osm
        packet = osm.mrm.broadcastHeader('BX', osm.me.ipp)
        packet.append(self.nextPktNum())
        self.signPacket(packet, broadcast=True)
        return ''.join(packet)


    def sendState(self):

        dcall_discard(self, 'sendState_dcall')

        def cb():
            self.sendState_dcall = None

            osm = self.main.osm

            assert (osm and osm.syncd)

            # Decide when to retransmit next
            when = 60 * 5
            self.sendState_dcall = reactor.callLater(when, cb)

            # Broadcast header
            packet = osm.mrm.broadcastHeader('BS', osm.me.ipp)

            # The meat
            block_hashes, blocks = self.getStateData(packet)

            # Signature
            self.signPacket(packet, broadcast=True)

            # Broadcast status message
            osm.mrm.newMessage(''.join(packet), mystatus=True)

            # Broadcast data blocks
            # This could potentially be a bottleneck for slow connections
            for b in blocks:
                packet = osm.mrm.broadcastHeader('BB', osm.me.ipp)
                packet.append(self.nextPktNum())
                packet.append(struct.pack("!H", len(b)))
                packet.append(b)
                osm.mrm.newMessage(''.join(packet))

        self.sendState_dcall = reactor.callLater(0, cb)


    def getStateData(self, packet):
        # All the state info common between BS and Br packets

        osm = self.main.osm
        assert (osm and osm.syncd)

        # Get the IRC Server, if it's ready
        ircs = self.main.ircs
        if ircs and (not ircs.syncd):
            ircs = None

        # Sequence number
        packet.append(self.nextPktNum())

        # Expiration time
        when = int(dcall_timeleft(self.sendState_dcall))
        packet.append(struct.pack("!H", when))

        # Session ID, uptime flags
        packet.append(osm.me.sesid)
        packet.append(struct.pack("!I", seconds() - osm.me.uptime))
        packet.append(struct.pack("!B", dtella.PERSIST_BIT))

        chunks = []

        # Add info strings
        self.addInfoChunk(chunks)

        if ircs:
            # Get IRC nick list
            nicks = set(ircs.data.getNicksInChan(cfg.irc_chan))
            nicks.update(cfg.virtual_nicks)
            nicks = list(nicks)
            nicks.sort()

            # Add the list of online nicks
            c = ircs.data.getChan(cfg.irc_chan)
            for nick in nicks:
                self.addNickChunk(
                    chunks, irc_to_dc(nick), c.getInfoIndex(nick))

        chunks = ''.join(chunks)

        # Split data string into 1k blocks
        blocks = []
        for i in range(0, len(chunks), 1024):
            blocks.append(chunks[i:i+1024])

        block_hashes = [md5.new(b).digest() for b in blocks]

        # Add the list of block hashes
        packet.append(struct.pack("!B", len(block_hashes)))
        packet.extend(block_hashes)

        # Add the public key
        pubkey = long_to_bytes(self.rsa_obj.n)
        packet.append(struct.pack("!H", len(pubkey)))
        packet.append(pubkey)

        # Return hashes and blocks
        return block_hashes, blocks


    def sendBridgeChange(self, chunks):
        osm = self.main.osm
        ircs = self.main.ircs

        assert (osm and osm.syncd and ircs and ircs.syncd)

        packet = osm.mrm.broadcastHeader('BC', osm.me.ipp)
        packet.append(self.nextPktNum())

        chunks = ''.join(chunks)
        packet.append(struct.pack("!H", len(chunks)))
        packet.append(chunks)

        self.signPacket(packet, broadcast=True)

        osm.mrm.newMessage(''.join(packet))


    def sendPrivateBridgeChange(self, n, chunks):

        osm = self.main.osm
        ircs = self.main.ircs
        ph = self.main.ph

        assert (osm and osm.syncd and ircs and ircs.syncd)

        chunks = ''.join(chunks)

        ack_key = self.nextPktNum()

        packet = ['bC']
        packet.append(osm.me.ipp)
        packet.append(ack_key)
        packet.append(n.nickHash())
        packet.append(struct.pack('!H', len(chunks)))
        packet.append(chunks)
        self.signPacket(packet, broadcast=False)
        packet = ''.join(packet)

        def fail_cb():
            print "bC failed."

        n.sendPrivateMessage(ph, ack_key, packet, fail_cb)


    def addNickChunk(self, chunks, nick, mode):
        chunks.append('N')
        chunks.append(struct.pack("!BB", mode, len(nick)))
        chunks.append(nick)


    def addInfoChunk(self, chunks):
        chunks.append('I')
        infos = '|'.join(mode_info)
        chunks.append(struct.pack("!H", len(infos)))
        chunks.append(infos)


    def addKickChunk(self, chunks, n, l33t, reason):

        # Pick a packet number that's a little bit ahead of what the node
        # is using, so that any status messages sent out by the node at
        # the same time will be overriden by the kick.
        
        n.status_pktnum = (n.status_pktnum + 3) % 0x100000000

        flags = 0

        chunks.append('K')
        chunks.append(n.ipp)
        chunks.append(struct.pack("!IB", n.status_pktnum, flags))
        chunks.append(struct.pack("!B", len(l33t)))
        chunks.append(l33t)
        chunks.append(struct.pack("!B", len(n.nick)))
        chunks.append(n.nick)
        chunks.append(struct.pack("!H", len(reason)))
        chunks.append(reason)


    def addChatChunk(self, chunks, nick, text, flags=0):

        chat_pktnum = self.main.osm.mrm.getPacketNumber_chat()

        chunks.append('C')
        chunks.append(struct.pack('!I', chat_pktnum))
        chunks.append(struct.pack('!BB', flags, len(nick)))
        chunks.append(nick)

        text = text[:512]
        chunks.append(struct.pack('!H', len(text)))
        chunks.append(text)


    def addMessageChunk(self, chunks, nick, text, flags=0):
        chunks.append('M')
        chunks.append(struct.pack('!BB', flags, len(nick)))
        chunks.append(nick)
        
        text = text[:512]
        chunks.append(struct.pack('!H', len(text)))
        chunks.append(text)


    def receivedBlockRequest(self, src_ipp, bhash):
        try:
            b = self.cached_blocks[bhash]
        except KeyError:
            print "Requested block not found"
            return

        b.scheduleExpire(self.cached_blocks, bhash)        

        packet = ['bB']
        packet.append(self.main.osm.me.ipp)
        packet.append(struct.pack('!H', len(b.data)))
        packet.append(b.data)

        ad = Ad().setRawIPPort(src_ipp)
        self.main.ph.sendPacket(''.join(packet), ad.getAddrTuple())


    def receivedPrivateMessage(self, src_ipp, ack_key,
                               src_nhash, dst_nick, text):

        osm = self.main.osm
        ircs = self.main.ircs

        ack_flags = 0

        try:
            # Make sure we're ready to receive it
            if not (osm and osm.syncd and ircs and ircs.readytosend):
                raise dtella.Reject

            try:
                n = osm.lookup_ipp[src_ipp]
            except KeyError:
                # Never heard of this node
                raise dtella.Reject

            if not n.expire_dcall:
                # Node isn't online
                raise dtella.Reject
            
            if src_nhash != n.nickHash():
                # Source nickhash mismatch
                raise dtella.Reject

            if ack_key not in n.msgkeys_in:
                # Haven't seen this message before, so handle it

                try:
                    dst_nick = irc_from_dc(dst_nick)
                except ValueError:
                    raise dtella.Reject
                
                if dst_nick not in ircs.data.ulist:
                    # User isn't on IRC
                    raise dtella.Reject

                ircs.sendLine(":%s PRIVMSG %s :%s" %
                              (dc_to_irc(n.nick), dst_nick, text))

            # Forget about this message in a minute
            n.schedulePMKeyExpire(ack_key)

        except dtella.Reject:
            ack_flags |= dtella.ACK_REJECT_BIT

        self.main.ph.sendAckPacket(src_ipp, dtella.ACK_PRIVATE,
                                   ack_flags, ack_key)


    def shutdown(self):
        dcall_discard(self, 'sendState_dcall')

        for b in self.cached_blocks.itervalues():
            dcall_discard(b, 'expire_dcall')


##############################################################################


class DtellaBridgeMain(object):
    def __init__(self):

        # IRC Server
        self.ircs = None

        # DC Handler (always None)
        self.dch = None

        # Initial Connection Manager
        self.icm = None

        # Neighbor Connection Manager
        self.osm = None

        self.reconnect_dcall = None
        self.reconnect_interval = dtella.RECONNECT_RANGE[0]

        # State Manager
        self.state = dtella_state.StateManager(self, 'dtella_bridge.state')

        # Pakcet Encoder
        self.pk_enc = dtella_crypto.PacketEncoder(dtella_local.network_key)

        # Peer Handler
        self.ph = BridgeServerProtocol(self)

        reactor.listenUDP(cfg.udp_port, self.ph)

        # Register a function that runs before shutting down
        reactor.addSystemEventTrigger('before', 'shutdown',
                                      self.cleanupOnExit)

        ircfactory = IRCFactory(self)
        reactor.connectTCP(cfg.irc_server, cfg.irc_port, ircfactory)

        self.startConnecting()


    def cleanupOnExit(self):
        print "Reactor is shutting down.  Doing cleanup."

        self.shutdown(final=True)
        self.state.saveState()

        # Cleanly close the IRC connection before terminating
        if self.ircs:
            return self.ircs.shutdown()


    def startConnecting(self):
        # If all the conditions are right, start connection procedure

        assert not (self.icm or self.osm)

        dcall_discard(self, 'reconnect_dcall')

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
                    self.shutdown(final=True)
                    self.showLoginStatus("Your IP address is not authorized to use this network.")

                else:
                    self.showLoginStatus("Port not forwarded.")
                    self.shutdown(final=True)

        self.ph.remap_ip = None
        self.icm = dtella.InitialContactManager(self, cb)


    def startNodeSync(self, node_ipps=()):
        # Determine my IP address and enable the osm

        assert not (self.icm or self.osm)

        # Reset the reconnect interval
        self.reconnect_interval = dtella.RECONNECT_RANGE[0]
        dcall_discard(self, 'reconnect_dcall')

        ad = Ad().setTextIP(cfg.my_ip)
        ad.port = self.state.udp_port

        my_ipp = ad.getRawIPPort()

        bsm = BridgeServerManager(self)

        # Enable the object that keeps us online
        self.osm = dtella.OnlineStateManager(self, my_ipp, node_ipps, bsm=bsm)


    def showLoginStatus(self, text, counter=None):
        print text


    def shutdown(self, final=False):
        # Do a total shutdown of this Dtella node

        if self.icm or self.osm:
            self.showLoginStatus("Shutting down.")

        dcall_discard(self, 'reconnect_dcall')

        # Shut down InitialContactManager
        if self.icm:
            self.icm.shutdown()
            self.icm = None

        # Shut down OnlineStateManager
        if self.osm:
            self.osm.shutdown()
            self.osm = None

        if final:
            # Final shutdown, don't reconnect.
            return

        # Decide how long to wait before reconnecting
        when = self.reconnect_interval * random.uniform(0.8, 1.2)

        # Increase the reconnect interval logarithmically
        self.reconnect_interval = min(self.reconnect_interval * 1.5,
                                      dtella.RECONNECT_RANGE[1])

        self.showLoginStatus("Reconnecting in %d seconds." % when)

        def cb():
            self.reconnect_dcall = None
            self.startConnecting()

        self.reconnect_dcall = reactor.callLater(when, cb)


    def getOnlineDCH(self):
        # Return DCH, iff it's fully online.
        return None


    def getStateObserver(self):
        # Return the IRC Server, iff it's fully online

        if not (self.osm and self.osm.syncd):
            return None

        if self.ircs and self.ircs.readytosend:
            return self.ircs

        return None
        

    def addMyIPReport(self, from_ad, my_ad):
        return


    def addIRCServer(self, ircs):
        assert (not self.ircs)
        self.ircs = ircs


    def removeIRCServer(self, ircs):
        assert ircs and (self.ircs is ircs)

        self.ircs = None

        # If the IRC server had been syncd, then broadcast a mostly-empty
        # status update to Dtella, to show that all the nicks are gone.
        osm = self.osm
        if (osm and osm.syncd and ircs.syncd):
            osm.bsm.sendState()


if __name__ == '__main__':
    dtMain = DtellaBridgeMain()
    dtMain.state.udp_port = cfg.udp_port

    for addr in cfg.ip_cache:
        dtMain.state.refreshPeer(Ad().setTextIPPort(addr), 0)
    
    reactor.run()


