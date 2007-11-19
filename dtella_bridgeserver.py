#!/usr/bin/env python

"""
Dtella - Bridge Server Module
Copyright (C) 2007  Dtella Labs (http://www.dtella.org/)
Copyright (C) 2007  Paul Marks (http://www.pmarks.net/)
Copyright (C) 2007  Jacob Feisley  (http://www.feisley.com/)

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

import dtella_core

from twisted.internet.protocol import ReconnectingClientFactory
from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet import reactor, defer, ssl
from twisted.python.runtime import seconds
import twisted.internet.error

from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA

import time
import struct
import md5
import random
import re
import binascii
from collections import deque

import dtella_state
import dtella_crypto
import dtella_local
import dtella_hostmask

import dtella_log

import dtella_dnslookup

from dtella_util import Ad, dcall_discard, dcall_timeleft, validateNick, CHECK
from dtella_core import Reject, BadPacketError, BadTimingError, NickError


import dtella_bridge_config as cfg

#Logging for Dtella Client
LOG = dtella_log.makeLogger("dtella.bridge.log", 4194304, 4)
LOG.debug("Bridge Logging Manager Initialized")

irc_nick_chars = (
    "-0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
    "abcdefghijklmnopqrstuvwxyz{|}")

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

B_USER = "dtbridge"
B_REALNAME = "Dtella Bridge"


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


def n_user(ipp):
    h = binascii.hexlify(md5.new(ipp).digest())[:6]
    return "dt" + h.upper()


def wild_to_regex(in_str):
    # Build a regular expression from a string containing *'s
    
    regex_badchars = r".^$+?{}\[]|():"

    out = '^'
    for c in in_str:
        if c == '*':
            out += '.*'
        elif c in regex_badchars:
            out += '\\' + c
        else:
            out += c
    out += '$'

    return re.compile(out, re.IGNORECASE)


def dc_to_irc(dnick):
    # Encode a DC nick, for use in IRC.

    reason = validateNick(dnick)
    if reason:
        raise NickError("Bad Dtella Nick: %s" % reason)

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

    if len(inick) > cfg.max_irc_nick_len:
        raise NickError("Your nick is too long.")

    return inick


def dc_from_irc(inick):
    # Decode an IRC-encoded DC nick, for use in Dtella.

    # Verify prefix
    if not inick.startswith(cfg.dc_to_irc_prefix):
        raise NickError("Bad prefix")

    dnick = inick[len(cfg.dc_to_irc_prefix):]

    if not dnick:
        raise NickError("Nothing after prefix")

    n_escapes = 0
    for c in dnick:
        if c == '`':
            n_escapes += 1

    if n_escapes:
        head, tail = dnick.rsplit('-', 1)
        escapes = base_convert(tail, base36_chars, escape_chars, n_escapes)

        if len(escapes) != n_escapes:
            raise NickError("Unknown escape sequence")

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
    if not dnick.startswith(cfg.irc_to_dc_prefix):
        raise NickError("Bad prefix")

    inick = dnick[len(cfg.irc_to_dc_prefix):].replace('!','|')

    if not inick:
        raise NickError("Nothing after prefix")

    for c in inick:
        if c not in irc_nick_chars:
            raise NickError("Invalid character: %s" % c)

    return inick


# Regex for color codes and other IRC stuff.
ircstrip_re = re.compile(
    "\x03[0-9]{1,2}(,[0-9]{1,2})?|[\x00-\x1F\x80-\xFF]")

def irc_strip(text):
    return ircstrip_re.sub('', text)


##############################################################################


class IRCServer(LineOnlyReceiver):
    showirc = False
    
    def __init__(self, main):
        self.data = IRCServerData(self)
        self.main = main
        self.syncd = False
        self.server_name = None
        self.shutdown_deferred = None

        self.ping_dcall = None
        self.ping_waiting = False


    def connectionMade(self):
        self.main.addIRCServer(self)
        self.sendLine("PASS :%s" % (cfg.irc_password,))
        self.sendLine("SERVER %s 1 :%s" % (cfg.my_host, cfg.my_name))


    def sendLine(self, line):
        line = line.replace('\r', '').replace('\n', '')
        
        if self.showirc:
            LOG.log(5, "<: %s" % line)
            
        LineOnlyReceiver.sendLine(self, line)


    def lineReceived(self, line):

        if not line:
            return

        if self.showirc:
            LOG.log(5, ">: %s" % line)

        if line[0] == ':':
            try:
                prefix, line = line[1:].split(' ', 1)
            except ValueError:
                return
        else:
            prefix = ''

        try:
            line, trailing = line.split(' :', 1)
        except ValueError:
            args = line.split()
        else:
            args = line.split()
            args.append(trailing)

        try:
            f = getattr(self, 'handleCmd_%s' % args[0].upper())
        except AttributeError:
            pass
        else:
            f(prefix, args[1:])


    def handleCmd_PING(self, prefix, args):
        LOG.info("PING? PONG!")
        if len(args) == 1:
            self.sendLine("PONG %s :%s" % (cfg.my_host, args[0]))
        elif len(args) == 2:
            self.sendLine("PONG %s :%s" % (args[1], args[0]))


    def handleCmd_PONG(self, prefix, args):
        if self.ping_waiting:
            self.ping_waiting = False
            self.schedulePing()


    def handleCmd_NICK(self, prefix, args):

        oldnick = prefix
        newnick = args[0]
        
        if newnick.startswith(cfg.irc_to_dc_prefix):
            self.sendLine(
                ":%s KILL %s :%s (nick reserved for Dtella)"
                % (cfg.my_host, newnick, cfg.my_host))
            return
            
        if oldnick:
            self.data.changeNick(oldnick, newnick)
        else:
            self.data.addNick(newnick)


    def handleCmd_JOIN(self, prefix, args):
        
        nick = prefix
        chans = args[0].split(',')

        if cfg.irc_chan in chans:
            self.data.gotJoin(nick)


    def handleCmd_PART(self, prefix, args):

        nick = prefix
        chans = args[0].split(',')

        if cfg.irc_chan in chans:
            self.data.gotPart(nick)


    def handleCmd_QUIT(self, prefix, args):

        nick = prefix
        self.data.gotQuit(nick)


    def handleCmd_KICK(self, prefix, args):

        chan = args[0]
        l33t = prefix
        n00b = args[1]
        reason = irc_strip(args[2])

        if chan == cfg.irc_chan:
            if n00b == cfg.dc_to_irc_bot:
                self.pushBotJoin()
            else:
                self.data.gotKick(l33t, n00b, reason)


    def handleCmd_KILL(self, prefix, args):

        # :darkhorse KILL }darkhorse :dhirc.com!darkhorse (TEST!!!)
        l33t = prefix
        n00b = args[0]
        reason = irc_strip(args[1])

        if n00b == cfg.dc_to_irc_bot:
            self.pushBotJoin(do_nick=True)
        else:
            self.data.gotKill(l33t, n00b, reason)


    def handleCmd_TOPIC(self, prefix, args):
        
        # :Paul TOPIC #dtella Paul 1169420711 :Dtella :: Development Stage
        chan = args[0]
        whoset = args[1]
        text = irc_strip(args[-1])

        if chan == cfg.irc_chan:
            self.data.gotTopic(whoset, text)


    def handleCmd_MODE(self, prefix, args):

        # :Paul MODE #dtella +vv aaahhh Big_Guy
        whoset = prefix
        chan = args[0]
        change = args[1]
        nicks = args[2:]

        if chan == cfg.irc_chan:
            self.data.gotChanModes(whoset, change, nicks)


    def handleCmd_TKL(self, prefix, args):

        #:irc1.dhirc.com TKL + Z * 128.10.12.0/24 darkhorse!admin@dhirc.com 0 1171427130 :no reason
        
        addrem = args[0]
        kind = args[1]

        osm = self.main.osm

        if kind == 'Z' and args[2] == '*':
            ipmask = args[3]

            try:
                ip, subnet = ipmask.split('/', 1)
            except ValueError:
                ip, subnet = ipmask, "32"

            try:
                ip, = struct.unpack('!i', Ad().setTextIP(ip).getRawIP())
            except (ValueError, struct.error):
                LOG.error( "Invalid IP format" )
                return

            LOG.debug( "ip= %s" % ip )

            try:
                subnet = int(subnet)
            except ValueError:
                LOG.error( "Subnet not a number")
                return

            if subnet == 0:
                mask = 0
            elif 1 <= subnet <= 32:
                mask = ~0 << (32-subnet)
            else:
                LOG.error( "Subnet out of range" )
                return

            LOG.info( "kind=" + kind )
            LOG.info( "ip,mask=%s, %s" % (ip, mask) )

            if addrem == '+':
                self.data.addNetBan(ip, mask)
            elif addrem == '-':
                self.data.removeNetBan(ip, mask)

        # :%s TKL + Q * %s* %s 0 %d :Reserved for Dtella

        elif kind == 'Q':
            nickmask = args[3]

            if addrem == '+':
                reason = args[-1]

                if nickmask == cfg.dc_to_irc_prefix + '*':
                    return
                
                self.data.qlines[nickmask] = (wild_to_regex(nickmask),
                                              reason)
                
                LOG.info( "Adding Qline: %s" % nickmask )

            elif addrem == '-':
                self.data.qlines.pop(nickmask, None)


    def handleCmd_SERVER(self, prefix, args):

        if prefix:
            # Not from our connected server
            return

        if self.server_name:
            # Could be a dupe?  Ignore it.
            return

        # We got a reply from the our connected IRC server, so our password
        # was just accepted.  Send the Dtella state information into IRC.

        # Save server name
        CHECK(args[0])
        self.server_name = args[0]

        osm = self.main.osm

        # Tell the ReconnectingClientFactory that we're cool
        self.factory.resetDelay()

        # Set up nick reservation
        self.sendLine(
            ":%s TKL + Q * %s* %s 0 %d :Reserved for Dtella" %
            (cfg.my_host, cfg.dc_to_irc_prefix,
             cfg.my_host, time.time()))

        # Send my own bridge nick
        self.pushBotJoin(do_nick=True)

        # Maybe send Dtella nicks
        if osm and osm.syncd:
            self.sendState()

        # This isn't very correct, because the Dtella nicks probably
        # haven't been sent yet, but it's the best we can practically do.
        self.sendLine(":%s EOS" % cfg.my_host)


    def handleCmd_EOS(self, prefix, args):

        if prefix != self.server_name:
            return

        LOG.info( "SYNCD!!!!" )

        self.showirc = True

        osm = self.main.osm

        # If we enter the syncd state, send status to Dtella, if Dtella
        # is ready.  Otherwise, Dtella will send its own state when it
        # becomes ready.

        if not self.syncd:
            self.syncd = True
            
            if osm and osm.syncd:
                osm.bsm.sendState()

            self.schedulePing()


    def handleCmd_WHOIS(self, prefix, args):
        # Somewhat simplistic handling of WHOIS requests
        
        if not (prefix and len(args) >= 1):
            return

        src = prefix
        who = args[0]

        if who == cfg.dc_to_irc_bot:
            self.pushWhoisReply(
                311, src, who, B_USER, cfg.my_host, '*', B_REALNAME)
            self.pushWhoisReply(
                312, src, who, cfg.my_host, cfg.my_name)
            self.pushWhoisReply(
                319, src, who, cfg.irc_chan)

        else:
            osm = self.main.osm

            if not (osm and osm.syncd):
                return

            try:
                n = osm.nkm.lookupNick(dc_from_irc(who))
            except (NickError, KeyError):
                return

            if not hasattr(n, 'hostmask'):
                return

            self.pushWhoisReply(
                311, src, who, n_user(n.ipp), n.hostmask, '*',
                "Dtella %s" % n.dttag[3:])
            self.pushWhoisReply(
                312, src, who, cfg.my_host, cfg.my_name)
            self.pushWhoisReply(
                319, src, who, cfg.irc_chan)

            if dtella_local.use_locations:
                self.pushWhoisReply(
                    320, src, who, "Location: %s"
                    % dtella_local.hostnameToLocation(n.hostname))

        self.pushWhoisReply(
            318, src, who, "End of /WHOIS list.")
            


    def pushWhoisReply(self, code, target, who, *strings):
        line = ":%s %d %s %s " % (cfg.my_host, code, target, who)
        strings = list(strings)
        strings[-1] = ":" + strings[-1]
        line += ' '.join(strings)
        self.sendLine(line)


    def handleCmd_PRIVMSG(self, prefix, args):

        osm = self.main.osm

        if not (self.syncd and osm and osm.syncd):
            return

        target = args[0]
        text = args[1]
        flags = 0
        
        if (text[:8], text[-1:]) == ('\001ACTION ', '\001'):
            text = text[8:-1]
            flags |= dtella_core.SLASHME_BIT

        text = irc_strip(text)

        if target == cfg.irc_chan:
            chunks = []
            osm.bsm.addChatChunk(
                chunks, irc_to_dc(prefix), text, flags)
            osm.bsm.sendBridgeChange(chunks)
	
        #Format> :Global PRIVMSG $irc3.dhirc.com :TESTING....
        #Handle global messages delivered to the bridge.
        elif target == "$" + cfg.my_host:
            flags |= dtella_core.NOTICE_BIT
            chunks = []
            osm.bsm.addChatChunk(
                chunks, irc_to_dc(prefix), text, flags)
            osm.bsm.sendBridgeChange(chunks)

        else:
            try:
                nick = dc_from_irc(target)
                n = osm.nkm.lookupNick(nick)
            except (NickError, KeyError):
                return

            chunks = []
            osm.bsm.addMessageChunk(
                chunks, irc_to_dc(prefix), text, flags)
            osm.bsm.sendPrivateBridgeChange(n, chunks)


    def handleCmd_NOTICE(self, prefix, args):

        osm = self.main.osm

        if not (self.syncd and osm and osm.syncd):
            return

        target = args[0]
        text = irc_strip(args[1])
        flags = dtella_core.NOTICE_BIT

        if target == cfg.irc_chan:
            chunks = []
            osm.bsm.addChatChunk(
                chunks, irc_to_dc(prefix), text, flags)
            osm.bsm.sendBridgeChange(chunks)

        else:
            try:
                nick = dc_from_irc(target)
                n = osm.nkm.lookupNick(nick)
            except (NickError, KeyError):
                return

            chunks = []
            osm.bsm.addMessageChunk(
                chunks, irc_to_dc(prefix), text, flags)
            osm.bsm.sendPrivateBridgeChange(n, chunks)


    def sendState(self):
        
        osm = self.main.osm
        CHECK(self.server_name and osm and osm.syncd)

        LOG.info( "Sending Dtella state to IRC..." )

        nicks = osm.nkm.nickmap.values()
        nicks.sort(key=lambda n: n.nick)

        for n in nicks:
            try:
                inick = self.checkIncomingNick(n)
            except NickError:
                osm.nkm.removeNode(n, "Bad Nick")
                n.setNoUser()
            else:
                # Ok, get ready to send to IRC
                n.inick = inick
                self.main.rdns.addRequest(n)


    def pushNick(self, nick, user, host, name):
        self.sendLine(
            "NICK %s 0 %d %s %s %s 1 :%s" %
            (nick, time.time(), user, host, cfg.my_host, name))


    def pushMode(self, nick, mode):
        self.sendLine(":%s MODE %s :%s" % (nick, nick, mode))


    def pushJoin(self, nick):
        self.sendLine(":%s JOIN %s" % (nick, cfg.irc_chan))


    def pushTopic(self, nick, topic):
        self.sendLine(
            ":%s TOPIC %s %s %d :%s" %
            (nick, cfg.irc_chan, nick, int(time.time()), topic))
        

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


    def pushBotJoin(self, do_nick=False):
        if do_nick:
            self.pushNick(
                cfg.dc_to_irc_bot, B_USER, cfg.my_host, B_REALNAME)

        self.pushJoin(cfg.dc_to_irc_bot)

        self.sendLine(
            ":%s MODE %s +ao %s %s" %
            (cfg.my_host, cfg.irc_chan, cfg.dc_to_irc_bot, cfg.dc_to_irc_bot))


    def schedulePing(self):

        if self.ping_dcall:
            self.ping_dcall.reset(60.0)
            return
        
        def cb():
            self.ping_dcall = None

            if self.ping_waiting:
                LOG.error( "Ping timeout!" )
                self.transport.loseConnection()
            else:
                self.sendLine("PING :%s" % cfg.my_host)
                self.ping_waiting = True
                self.ping_dcall = reactor.callLater(60.0, cb)

        self.ping_dcall = reactor.callLater(60.0, cb)


    def updateTopic(self, n, topic):

        osm = self.main.osm
        CHECK(self.syncd and osm and osm.syncd)

        # Check if the topic is locked
        if self.data.topic_locked:
            return False

        # Update IRC topic
        self.data.topic = topic
        self.data.topic_whoset = n.nick
        try:
            self.pushTopic(n.inick, topic)
        except NickError:
            return False

        # Broadcast change
        chunks = []
        osm.bsm.addTopicChunk(chunks, n.nick, topic, changed=True)
        osm.bsm.sendBridgeChange(chunks)

        return True


    def checkIncomingNick(self, n):
        try:
            inick = dc_to_irc(n.nick)

            for q, reason in self.data.qlines.itervalues():
                if q.match(inick):
                    raise NickError("Nick '%s' is Q-lined: %s" % (n.nick, reason))

            LOG.debug( "Nick '%s' is okay" % n.nick )

        except NickError, e:
            LOG.debug( "Nick is not okay" )
            # Bad nick.  KICK!
            osm = self.main.osm
            chunks = []
            osm.bsm.addKickChunk(
                chunks, n, cfg.irc_to_dc_bot, str(e),
                rejoin=False, silent=True)
            osm.bsm.sendBridgeChange(chunks)
            raise

        return inick


    def event_AddNick(self, n):
        # Might raise NickError
        inick = self.checkIncomingNick(n)

        n.inick = inick
        self.main.rdns.addRequest(n)

        n.jointime = time.time()


    def event_RemoveNick(self, n, reason):
        if hasattr(n, 'inick') and not hasattr(n, 'dns_pending'):

            try:
                t = n.jointime
            except AttributeError:
                pass
            else:
                reason += " [%d sec]" % int(time.time() - t)
            
            self.pushQuit(n.inick, reason)


    def event_UpdateInfo(self, n):
        pass


    def event_ChatMessage(self, n, nick, text, flags):

        CHECK(not hasattr(n, 'dns_pending'))

        if flags & dtella_core.NOTICE_BIT:
            self.pushNotice(n.inick, text)
        elif flags & dtella_core.SLASHME_BIT:
            self.pushPrivMsg(n.inick, text, action=True)
        else:
            self.pushPrivMsg(n.inick, text)


    def shutdown(self):

        if self.shutdown_deferred:
            return self.shutdown_deferred
        
        # Remove nick ban
        self.sendLine(
            ":%s TKL - Q * %s* %s" %
            (cfg.my_host, cfg.dc_to_irc_prefix, cfg.my_host)
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
            self.chanmodes = []


    def __init__(self, ircs):
        self.ircs = ircs
        
        self.users = {} # nick -> User()
        self.chanusers = set()

        self.topic = ""
        self.topic_whoset = ""
        self.topic_locked = False

        self.moderated = False

        self.chanbans = {}  # string -> compiled regex
        self.qlines = {}  # string -> compiled regex

        self.bans = set()  # network bans: 2 ints: (ip, mask)


    def addNick(self, nick):
        self.users[nick] = self.User(nick)


    def changeNick(self, oldnick, newnick):
        try:
            u = self.users.pop(oldnick)
        except KeyError:
            LOG.debug( "Nick doesn't exist" )
            return

        if newnick in self.users:
            LOG.debug( "New nick already exists!" )
            return

        u.nick = newnick
        self.users[newnick] = u

        if u in self.chanusers:

            osm = self.ircs.main.osm
            if (self.ircs.syncd and osm and osm.syncd):

                infoindex = self.getInfoIndex(newnick)
                
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


    def gotKick(self, l33t, n00b, reason):

        osm = self.ircs.main.osm
        if (self.ircs.syncd and osm and osm.syncd):

            try:
                nick = dc_from_irc(n00b)
                n = osm.nkm.lookupNick(nick)
            except (NickError, KeyError):
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
                    chunks, n, irc_to_dc(l33t), reason,
                    rejoin=True, silent=False
                    )
                osm.bsm.sendBridgeChange(chunks)

                # Forget this nick
                osm.nkm.removeNode(n, "Kicked")
                n.setNoUser()

        try:
            u = self.users[n00b]
        except KeyError:
            LOG.debug( "Nick doesn't exist" )
            return

        self.chanusers.remove(u)


    def gotKill(self, l33t, n00b, reason):

        osm = self.ircs.main.osm
        if (self.ircs.syncd and osm and osm.syncd):

            try:
                nick = dc_from_irc(n00b)
                n = osm.nkm.lookupNick(nick)
            except (NickError, KeyError):
                # IRC Nick; see if they're in the channel.
                try:
                    u = self.users[n00b]
                    if u not in self.chanusers:
                        raise KeyError
                except KeyError:
                    pass
                else:
                    # IRC nick, in the channel
                    chunks = []
                    osm.bsm.addChatChunk(
                        chunks, cfg.irc_to_dc_bot,
                        "%s has KILL'd %s: %s" %
                        (irc_to_dc(l33t), irc_to_dc(n00b), reason)
                        )
                    osm.bsm.addNickChunk(chunks, irc_to_dc(n00b), 0xFF)
                    osm.bsm.sendBridgeChange(chunks)
            else:
                # DC Nick
                chunks = []
                osm.bsm.addKickChunk(
                    chunks, n, irc_to_dc(l33t), ("KILL: %s" % reason),
                    rejoin=True, silent=False
                    )
                osm.bsm.sendBridgeChange(chunks)

                # Forget this nick
                del n.inick
                osm.nkm.removeNode(n, "Killed")
                n.setNoUser()

        # Forget this nick
        try:
            u = self.users.pop(n00b)
        except KeyError:
            return

        self.chanusers.discard(u)


    def gotJoin(self, nick):
        try:
            u = self.users[nick]
        except KeyError:
            print "nick %s doesn't exist!" % (nick,)
            return

        if u in self.chanusers:
            LOG.warning( "already in channel!" )
            return

        self.chanusers.add(u)

        u.chanmodes = [False] * len(chan_umodes)

        osm = self.ircs.main.osm
        if (self.ircs.syncd and osm and osm.syncd):

            infoindex = self.getInfoIndex(nick)
            
            chunks = []
            osm.bsm.addNickChunk(
                chunks, irc_to_dc(nick), infoindex)
            osm.bsm.sendBridgeChange(chunks)


    def gotChanModes(self, whoset, change, nicks):

        val = True
        i = 0

        osm = self.ircs.main.osm

        unset_modes = []
        unset_nicks = []

        chunks = []

        for c in change:
            if c == '+':
                val = True
            elif c == '-':
                val = False
            elif c == 't':
                self.topic_locked = val
            elif c == 'm':
                self.moderated = val
                if osm and osm.syncd:
                    osm.bsm.addModeratedChunk(chunks, val)
            elif c == 'k':
                # Skip over channel key
                i += 1
            elif c == 'l':
                # Skip over channel user limit
                i += 1
            elif c == 'b':
                banmask = nicks[i]
                i += 1
                if val:
                    self.chanbans[banmask] = wild_to_regex(banmask)
                else:
                    self.chanbans.pop(banmask, None)
                LOG.debug( "bans= %s" % self.chanbans.keys() )
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

                try:
                    u = self.users[nick]
                except KeyError:
                    try:
                        if not (osm and osm.syncd):
                            raise NickError("Not online yet")
                        osm.nkm.lookupNick(dc_from_irc(nick))
                    except (NickError, KeyError):
                        continue

                    # If we're setting a mode for a Dt node, unset it.
                    if val:
                        unset_modes.append(c)
                        unset_nicks.append(nick)
                    continue

                old_infoindex = self.getInfoIndex(nick)
                u.chanmodes[modeidx] = val
                new_infoindex = self.getInfoIndex(nick)

                if new_infoindex == old_infoindex:
                    continue

                if osm:
                    osm.bsm.addNickChunk(
                        chunks, irc_to_dc(nick), new_infoindex)

        if self.ircs.syncd and osm and osm.syncd:

            # Might want to make this formatted better
            text = ' '.join([change]+nicks)

            osm.bsm.addChatChunk(
                chunks, cfg.irc_to_dc_bot,
                "%s sets mode: %s" % (irc_to_dc(whoset), text)
                )

            osm.bsm.sendBridgeChange(chunks)

        if unset_modes:
            self.ircs.sendLine(
                ":%s MODE %s -%s %s" % (
                    cfg.dc_to_irc_bot, cfg.irc_chan,
                    ''.join(unset_modes), ' '.join(unset_nicks)))


    def nodeBannedInChan(self, n):

        h1 = "%s!%s@%s" % (n.inick, n_user(n.ipp), n.hostname)
        h2 = "%s!%s@%s" % (n.inick, n_user(n.ipp), n.hostmask)
        
        for ban_re in self.chanbans.itervalues():
            if ban_re.match(h1) or ban_re.match(h2):
                return True

        return False


    def addNetBan(self, ip, mask):
        
        if (ip, mask) in self.bans:
            LOG.warning( "Duplicate ban" )
            return

        self.bans.add((ip, mask))

        LOG.info( "* Ban Added" )

        osm = self.ircs.main.osm

        if (self.ircs.syncd and osm and osm.syncd):
            chunks = []
            osm.bsm.addBanChunk(chunks, ip, mask, True)
            osm.bsm.sendBridgeChange(chunks)

        if osm:
            osm.banm.enforceNewBan((ip, mask))


    def removeNetBan(self, ip, mask):

        try:
            self.bans.remove((ip, mask))
        except KeyError:
            LOG.warning( "Ban not found" )
            return

        LOG.info( "* Ban Removed" )

        osm = self.ircs.main.osm

        if (self.ircs.syncd and osm and osm.syncd):
            chunks = []
            osm.bsm.addBanChunk(chunks, ip, mask, False)
            osm.bsm.sendBridgeChange(chunks)


    def gotQuit(self, nick):
        try:
            u = self.users.pop(nick)
        except KeyError:
            print "nick %s doesn't exist!" % (nick,)
            return

        try:
            self.chanusers.remove(u)
        except KeyError:
            return

        osm = self.ircs.main.osm

        if (self.ircs.syncd and osm and osm.syncd):
            chunks = []
            osm.bsm.addNickChunk(chunks, irc_to_dc(nick), 0xFF)
            osm.bsm.sendBridgeChange(chunks)


    def gotPart(self, nick):
        try:
            u = self.users[nick]
        except KeyError:
            print "nick %s doesn't exist!" % (nick,)
            return

        try:
            self.chanusers.remove(u)
        except KeyError:
            return

        osm = self.ircs.main.osm
        if (self.ircs.syncd and osm and osm.syncd):
            chunks = []
            osm.bsm.addNickChunk(chunks, irc_to_dc(nick), 0xFF)
            osm.bsm.sendBridgeChange(chunks)


    def gotTopic(self, whoset, topic):

        try:
            # DC nick
            whoset = dc_from_irc(whoset)
        except NickError:
            # IRC nick
            whoset = irc_to_dc(whoset)

        self.topic = topic
        self.topic_whoset = whoset
        
        osm = self.ircs.main.osm
        if (self.ircs.syncd and osm and osm.syncd):
            chunks = []
            osm.bsm.addTopicChunk(
                chunks, whoset, topic, changed=True)
            osm.bsm.sendBridgeChange(chunks)


    def getInfoIndex(self, nick):
        # Get the Dtella info index for this user
        try:
            u = self.users[nick]
        except KeyError:
            # shouldn't really happen
            return 6

        if u not in self.chanusers:
            # virtual
            return 6
        
        try:
            # qaohv
            return u.chanmodes.index(True)
        except ValueError:
            # plain user
            return 5


    def getNicksInChan(self):
        nicks = [u.nick for u in self.chanusers]
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


class BridgeServerProtocol(dtella_core.PeerHandler):

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


    def handlePacket_bT(self, ad, data):
        # Topic change request

        (kind, src_ipp, ack_key, src_nhash, rest
         ) = self.decodePacket('!2s6s8s4s+', data)

        self.checkSource(src_ipp, ad)

        (topic, rest
         ) = self.decodeString1(rest)

        if rest:
            raise BadPacketError("Extra data")

        osm = self.main.osm
        if not (osm and osm.syncd):
            raise BadTimingError("Not ready for bT")

        osm.bsm.receivedTopicChange(src_ipp, ack_key, src_nhash, topic)


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


    def isModerated(self):
        ircs = self.main.ircs
        return (ircs and ircs.data.moderated)


    def nextPktNum(self):

        t = long(time.time())

        if self.bridge_pktnum >> 24 == t:
            self.bridge_pktnum += 1
            LOG.debug( "nextPktNum: Incrementing" )
        else:
            self.bridge_pktnum = (t << 24L)
            LOG.debug( "nextPktNum: New Time" )

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
        if ircs and ircs.server_name:
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
        LOG.debug( "Sign Time= %s" % (time.time() - t) )

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

            CHECK(osm and osm.syncd)

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
            osm.mrm.newMessage(''.join(packet), tries=8)

            # Broadcast data blocks
            # This could potentially be a bottleneck for slow connections
            for b in blocks:
                packet = osm.mrm.broadcastHeader('BB', osm.me.ipp)
                packet.append(self.nextPktNum())
                packet.append(struct.pack("!H", len(b)))
                packet.append(b)
                osm.mrm.newMessage(''.join(packet), tries=4)

        self.sendState_dcall = reactor.callLater(0, cb)


    def getStateData(self, packet):
        # All the state info common between BS and Br packets

        osm = self.main.osm
        CHECK(osm and osm.syncd)

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
        packet.append(struct.pack("!I", int(seconds() - osm.me.uptime)))
        packet.append(struct.pack("!B", dtella_core.PERSIST_BIT))

        chunks = []

        # Add info strings
        self.addInfoChunk(chunks)

        if (ircs and ircs.syncd):
            # Get IRC nick list
            nicks = set(ircs.data.getNicksInChan())
            nicks.update(cfg.virtual_nicks)
            nicks = list(nicks)
            nicks.sort()

            data = ircs.data

            # Add the list of online nicks
            for nick in nicks:
                self.addNickChunk(
                    chunks, irc_to_dc(nick), data.getInfoIndex(nick))

            self.addTopicChunk(
                chunks, data.topic_whoset, data.topic, changed=False)

            # Get bans list
            for ip, mask in data.bans:
                self.addBanChunk(chunks, ip, mask, True)

            if data.moderated:
                self.addModeratedChunk(chunks, True)

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

        CHECK(osm and osm.syncd)

        packet = osm.mrm.broadcastHeader('BC', osm.me.ipp)
        packet.append(self.nextPktNum())

        chunks = ''.join(chunks)
        packet.append(struct.pack("!H", len(chunks)))
        packet.append(chunks)

        self.signPacket(packet, broadcast=True)

        osm.mrm.newMessage(''.join(packet), tries=4)


    def sendPrivateBridgeChange(self, n, chunks):

        osm = self.main.osm
        ph = self.main.ph

        CHECK(osm and osm.syncd)

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

        def fail_cb(detail):
            print "bC failed: %s" % detail

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


    def addKickChunk(self, chunks, n, l33t, reason, rejoin, silent):

        # Pick a packet number that's a little bit ahead of what the node
        # is using, so that any status messages sent out by the node at
        # the same time will be overriden by the kick.
        
        n.status_pktnum = (n.status_pktnum + 3) % 0x100000000

        flags = (rejoin and dtella_core.REJOIN_BIT)

        chunks.append('K')
        chunks.append(n.ipp)
        chunks.append(struct.pack("!IB", n.status_pktnum, flags))
        chunks.append(struct.pack("!B", len(l33t)))
        chunks.append(l33t)

        if silent:
            n00b = ''
        else:
            n00b = n.nick
        
        chunks.append(struct.pack("!B", len(n00b)))
        chunks.append(n00b)
        chunks.append(struct.pack("!H", len(reason)))
        chunks.append(reason)


    def addBanChunk(self, chunks, ip, mask, enable):

        subnet = 0
        b = ~0 << 31
        while ((b & mask) == b) and (subnet < 32):
            b >>= 1
            subnet += 1

        if subnet == 0 and mask != 0:
            raise ValueError

        subnet |= (enable and 0x80)

        chunks.append('B')
        chunks.append(struct.pack('!Bi', subnet, ip))


    def addChatChunk(self, chunks, nick, text, flags=0):

        chat_pktnum = self.main.osm.mrm.getPacketNumber_chat()

        chunks.append('C')
        chunks.append(struct.pack('!I', chat_pktnum))
        chunks.append(struct.pack('!BB', flags, len(nick)))
        chunks.append(nick)

        text = text[:512]
        chunks.append(struct.pack('!H', len(text)))
        chunks.append(text)


    def addTopicChunk(self, chunks, nick, topic, changed):

        flags = (changed and dtella_core.CHANGE_BIT)

        chunks.append('T')
        chunks.append(struct.pack('!BB', flags, len(nick)))
        chunks.append(nick)

        topic = topic[:255]
        chunks.append(struct.pack('!B', len(topic)))
        chunks.append(topic)


    def addMessageChunk(self, chunks, nick, text, flags=0):
        chunks.append('M')
        chunks.append(struct.pack('!BB', flags, len(nick)))
        chunks.append(nick)
        
        text = text[:512]
        chunks.append(struct.pack('!H', len(text)))
        chunks.append(text)


    def addModeratedChunk(self, chunks, enable):
        flags = (enable and dtella_core.MODERATED_BIT)
        chunks.append('F')
        chunks.append(struct.pack('!B', flags))


    def receivedBlockRequest(self, src_ipp, bhash):
        try:
            b = self.cached_blocks[bhash]
        except KeyError:
            LOG.warning( "Requested block not found" )
            return

        b.scheduleExpire(self.cached_blocks, bhash)

        packet = ['bB']
        packet.append(self.main.osm.me.ipp)
        packet.append(struct.pack('!H', len(b.data)))
        packet.append(b.data)

        ad = Ad().setRawIPPort(src_ipp)
        self.main.ph.sendPacket(''.join(packet), ad.getAddrTuple())


    def nickRemoved(self, n):

        dels = ('dns_pending', 'hostname', 'hostmask', 'inick', 'jointime')

        for d in dels:
            try:
                delattr(n, d)
            except AttributeError:
                pass


    def receivedPrivateMessage(self, src_ipp, ack_key,
                               src_nhash, dst_nick, text):

        osm = self.main.osm
        ircs = self.main.ircs

        ack_flags = 0

        try:
            if not (osm and osm.syncd and ircs and ircs.server_name):
                raise Reject("Not ready for bridge PM")

            try:
                n = osm.lookup_ipp[src_ipp]
            except KeyError:
                raise Reject("Unknown source node")

            if not n.expire_dcall:
                raise Reject("Source node not online")

            if src_nhash != n.nickHash():
                raise Reject("Source nickhash mismatch")

            if hasattr(n, 'dns_pending'):
                raise Reject("Still waiting for DNS")

            if n.pokePMKey(ack_key):
                # Haven't seen this message before, so handle it

                try:
                    dst_nick = irc_from_dc(dst_nick)
                except NickError:
                    raise Reject("Invalid dest nick")
                
                if dst_nick not in ircs.data.users:
                    raise Reject("Dest not on IRC")

                ircs.pushPrivMsg(n.inick, text, dst_nick)

        except Reject:
            ack_flags |= dtella_core.ACK_REJECT_BIT

        self.main.ph.sendAckPacket(src_ipp, dtella_core.ACK_PRIVATE,
                                   ack_flags, ack_key)


    def receivedTopicChange(self, src_ipp, ack_key, src_nhash, topic):
        osm = self.main.osm
        ircs = self.main.ircs

        ack_flags = 0

        try:
            if not (osm and osm.syncd and ircs and ircs.syncd):
                raise Reject("Not ready for topic change")

            try:
                n = osm.lookup_ipp[src_ipp]
            except KeyError:
                raise Reject("Unknown node")

            if not n.expire_dcall:
                raise Reject("Node isn't online")

            if src_nhash != n.nickHash():
                raise Reject("Source nickhash mismatch")

            if hasattr(n, 'dns_pending'):
                raise Reject("Still waiting for DNS")

            if n.pokePMKey(ack_key):
                # Haven't seen this message before, so handle it

                if not ircs.updateTopic(n, topic):
                    raise Reject("Topic locked")

        except Reject:
            ack_flags |= dtella_core.ACK_REJECT_BIT

        self.main.ph.sendAckPacket(
            src_ipp, dtella_core.ACK_PRIVATE, ack_flags, ack_key)


    def shutdown(self):
        dcall_discard(self, 'sendState_dcall')

        for b in self.cached_blocks.itervalues():
            dcall_discard(b, 'expire_dcall')


##############################################################################


class ReverseDNSManager(object):

    class Entry(object):
        def __init__(self):
            self.waiting_ipps = set()
            self.hostname = None


    def __init__(self, main):
        self.main = main
        self.cache = {}  # raw ip -> Entry object

        # Queue of pending DNS requests
        self.dnsq = deque()

        # Number of simultaneous requests available
        self.limiter = 3


    def addRequest(self, n):
        ipp = n.ipp
        ip = ipp[:4]

        n.dns_pending = True

        try:
            ent = self.cache[ip]
        except KeyError:
            ent = self.cache[ip] = self.Entry()

        if ent.hostname:
            # Already have a hostname, sign on really soon
            reactor.callLater(0, self.signOn, ipp, ent.hostname)

        elif ent.waiting_ipps:
            # This hostname is already being queried.
            ent.waiting_ipps.add(ipp)

        else:
            # Start querying
            ent.waiting_ipps.add(ipp)
            self.dnsq.append((ip, ent))
            self.advanceQueue()


    def advanceQueue(self):

        # Only continue if we have a queue, and spare capacity
        if not (self.dnsq and self.limiter > 0):
            return

        self.limiter -= 1
        ip, ent = self.dnsq.popleft()

        def cb(hostname):
          
            for ipp in ent.waiting_ipps:
                self.signOn(ipp, hostname)

            ent.waiting_ipps.clear()

            if hostname is None:
                del self.cache[ip]
            else:
                ent.hostname = hostname

            self.limiter += 1
            self.advanceQueue()

        LOG.debug( "Querying %s" % Ad().setRawIP(ip).getTextIP())
        dtella_dnslookup.ipToHostname(Ad().setRawIP(ip), cb)


    def signOn(self, ipp, hostname):

        osm = self.main.osm
        ircs = self.main.ircs

        if not (osm and osm.syncd):
            return

        try:
            n = osm.lookup_ipp[ipp]
        except KeyError:
            return

        try:
            del n.dns_pending
        except AttributeError:
            return

        if not (ircs and ircs.server_name):
            return

        if hostname is None:
            hostname = Ad().setRawIPPort(ipp).getTextIP()
            hostmask = dtella_hostmask.mask_ipv4(hostname)
        else:
            hostmask = dtella_hostmask.mask_hostname(hostname)

        n.hostname = hostname
        n.hostmask = hostmask

        # Check channel ban
        if ircs.data.nodeBannedInChan(n):
            chunks = []
            osm.bsm.addKickChunk(
                chunks, n, cfg.irc_to_dc_bot, "Channel Ban",
                rejoin=True, silent=True)
            osm.bsm.sendBridgeChange(chunks)

            # Remove from Dtella nick list
            del n.inick
            osm.nkm.removeNode(n, "ChanBanned")
            n.setNoUser()
            return

        inick = n.inick

        ircs.pushNick(
            inick, n_user(n.ipp), hostname, "Dtella %s" % n.dttag[3:])
        ircs.pushMode(inick, "+iwx")
        ircs.pushJoin(inick)

        # Send queued chat messages
        osm.cms.flushQueue(n)


##############################################################################


class DNSUpdateManager(object):

    # Calls the 'dnsup_update_func' function in dtella_bridge_config,
    # which accepts a dictionary of key=value pairs, and returns a twisted
    # Deferred object.  We currently have a module which writes to a text
    # file, and another which performs a Dynamic DNS update.  Other modules
    # could potentially be written for free DNS hosting services.
    
    def __init__(self, main):
        self.main = main
        self.update_dcall = None
        self.busy = False

        self.scheduleUpdate(30.0)


    def scheduleUpdate(self, when):

        if self.update_dcall or self.busy:
            return

        def cb():
            self.update_dcall = None
            entries = self.getEntries()

            self.busy = True
            
            d = cfg.dnsup_update_func(entries)
            d.addCallback(self.updateSuccess)
            d.addErrback(self.updateFailed)

        self.update_dcall = reactor.callLater(when, cb)


    def updateSuccess(self, result):
        self.busy = False

        LOG.debug("DNS Update Successful: %s" % result)
        
        self.scheduleUpdate(cfg.dnsup_interval)


    def updateFailed(self, why):
        self.busy = False

        LOG.warning("DNS Update Failed: %s" % why)
        
        self.scheduleUpdate(cfg.dnsup_interval)


    def getEntries(self):
        # Build and return a dict of entries which should be sent to DNS

        def b64(arg):
            return binascii.b2a_base64(arg).rstrip()
        
        # Dictionary of key=value pairs to return.
        # Start out with the static entries provided in the config.
        entries = cfg.dnsup_fixed_entries.copy()

        osm = self.main.osm

        # Generate public key hash
        if cfg.private_key:
            pubkey = long_to_bytes(RSA.construct(cfg.private_key).n)
            entries['pkhash'] = b64(md5.new(pubkey).digest())

        # Collect IPPs for the ipcache string
        GOAL = 10
        ipps = set()

        # Initially add all the exempt IPs, without a port
        for ip in self.main.state.exempt_ips:
            ad = Ad()
            ad.ip = ip
            ad.port = 0
            ipps.add(ad.getRawIPPort())

        # Helper function to add an IPP, overriding any portless entries.
        def add_ipp(ipp):
            ipps.discard(ipp[:4] + '\0\0')
            ipps.add(ipp)

        # Add my own IP
        if osm:
            add_ipp(osm.me.ipp)
        else:
            try:
                add_ipp(self.main.selectMyIP())
            except ValueError:
                pass

        # Add the IPPs of online nodes
        if (osm and osm.syncd):

            now = time.time()

            def n_uptime(n):
                uptime = max(0, now - n.uptime)
                if n.persist:
                    uptime *= 1.5
                return -uptime
            
            nodes = osm.nodes[:]
            nodes.sort(key=n_uptime)

            for n in nodes:
                add_ipp(n.ipp)
                if len(ipps) >= GOAL:
                    break

        # Add the IPPs of offline nodes (if necessary)
        if len(ipps) < GOAL:
            for when,ipp in self.main.state.getYoungestPeers(GOAL):
                add_ipp(ipp)

                if len(ipps) >= GOAL:
                    break

        ipcache = list(ipps)
        random.shuffle(ipcache)

        ipcache = '\xFF\xFF\xFF\xFF' + ''.join(ipcache)
        ipcache = b64(self.main.pk_enc.encrypt(ipcache))

        entries['ipcache'] = ipcache

        return entries


##############################################################################


class DtellaMain_Bridge(dtella_core.DtellaMain_Base):

    def __init__(self):
        dtella_core.DtellaMain_Base.__init__(self)

        # State Manager
        self.state = dtella_state.StateManager(
            self, 'dtella_bridge.state', dtella_state.bridge_loadsavers)
        self.state.initLoad()
        
        self.state.persistent = True
        self.state.udp_port = cfg.udp_port

        # Add an inital value for my own IP, adding it to the exempt list
        # if it's offsite.
        if cfg.myip_hint:
            ad = Ad().setAddrTuple((cfg.myip_hint, cfg.udp_port))
            self.state.addExemptIP(ad)
            self.addMyIPReport(ad, ad)

        # Add pre-defined entries to my local cache, and add them to
        # the exempt list of they're offsite.
        for text_ipp in cfg.ip_cache:
            ad = Ad().setTextIPPort(text_ipp)
            self.state.addExemptIP(ad)
            self.state.refreshPeer(ad, 0)

        # Peer Handler
        self.ph = BridgeServerProtocol(self)

        # Reverse DNS Manager
        self.rdns = ReverseDNSManager(self)

        # DNS Update Manager
        self.dum = DNSUpdateManager(self)

        # Bind UDP Port
        try:
            reactor.listenUDP(cfg.udp_port, self.ph)
        except twisted.internet.error.BindError:
            LOG.error("Failed to bind UDP port!")
            raise SystemExit

        # IRC Server
        self.ircs = None

        self.startConnecting()


    def cleanupOnExit(self):
        LOG.info("Reactor is shutting down.  Doing cleanup.")

        self.shutdown(reconnect='no')
        self.state.saveState()

        # Cleanly close the IRC connection before terminating
        if self.ircs:
            return self.ircs.shutdown()


    def startConnecting(self):
        self.startInitialContact()


    def reconnectDesired(self):
        return True


    def getBridgeManager(self):
        return {'bsm': BridgeServerManager(self)}


    def logPacket(self, text):
        #print "pkt: %s" % text
        pass


    def showLoginStatus(self, text, counter=None):
        LOG.info( text )


    def queryLocation(self, my_ipp):
        pass


    def shutdown_NotifyObservers(self):
        # TODO: maybe print a message to IRC saying Dtella sync was lost
        pass


    def getOnlineDCH(self):
        # BridgeServer has no DC Handler
        return None


    def getStateObserver(self):
        # Return the IRC Server, iff it's fully online

        if not (self.osm and self.osm.syncd):
            return None

        if self.ircs and self.ircs.server_name:
            return self.ircs

        return None


    def addIRCServer(self, ircs):
        CHECK(not self.ircs)
        self.ircs = ircs


    def removeIRCServer(self, ircs):
        CHECK(ircs and (self.ircs is ircs))

        self.ircs = None

        # If the IRC server had been syncd, then broadcast a mostly-empty
        # status update to Dtella, to show that all the nicks are gone.
        osm = self.osm
        if (osm and osm.syncd and ircs.syncd):
            osm.bsm.sendState()

        # Cancel all the nick-specific state
        if osm:
            for n in self.osm.nodes:
                n.nickRemoved(self)


if __name__ == '__main__':
    
    dtMain = DtellaMain_Bridge()

    if cfg.irc_server:
        ifactory = IRCFactory(dtMain)
        if cfg.irc_ssl:
            sslContext = ssl.ClientContextFactory()
            reactor.connectSSL(cfg.irc_server, cfg.irc_port, ifactory, sslContext)
        else:
            reactor.connectTCP(cfg.irc_server, cfg.irc_port, ifactory)
    else:
        LOG.info("IRC is not enabled.")

    reactor.run()
