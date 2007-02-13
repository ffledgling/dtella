#!/usr/bin/env python

"""
Dtella - Bridge Server Module
Copyright (C) 2007  Dtella Labs (http://www.dtella.org)
Copyright (C) 2007  Paul Marks, Jacob Feisley

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
from twisted.internet import reactor, defer
from twisted.python.runtime import seconds
import twisted.internet.error

from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.PublicKey import RSA

import time
import struct
import md5
import random
import re
from collections import deque

import dtella_state
import dtella_crypto
import dtella_local
import dtella_hostmask

import dtella_dnslookup

from dtella_util import Ad, dcall_discard, dcall_timeleft, validateNick
from dtella_core import Reject, BadPacketError, BadTimingError, NickError


import dtella_bridge_config as cfg


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
    if len(inick) <= 1 or inick[0] != cfg.dc_to_irc_prefix:
        raise NickError("Bad prefix")

    dnick = inick[1:]

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
    if len(dnick) <= 1 or dnick[0] != cfg.irc_to_dc_prefix:
        raise NickError("Bad prefix")

    inick = dnick[1:].replace('!','|')

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

        if not line:
            return

        if self.showirc:
            print ">:", line

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
        print "PING? PONG!"
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
        
        if newnick[:1] == cfg.irc_to_dc_prefix:
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
            self.data.gotKick(l33t, n00b, reason)


    def handleCmd_KILL(self, prefix, args):

        # :darkhorse KILL }darkhorse :dhirc.com!darkhorse (TEST!!!)
        l33t = prefix
        n00b = args[0]
        reason = irc_strip(args[1])
        
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


    def handleCmd_SERVER(self, prefix, args):

        # If we receive this, our password was accepted, so broadcast
        # the Dtella state information if it's available and we haven't
        # sent it already.

        if self.readytosend:
            return

        self.readytosend = True

        osm = self.main.osm

        # Tell the ReconnectingClientFactory that we're cool
        self.factory.resetDelay()

        # Set up nick reservation
        self.sendLine(
            ":%s TKL + Q * %s* %s 0 %d :Reserved for Dtella" %
            (cfg.my_host, cfg.dc_to_irc_prefix,
             cfg.my_host, time.time()))

        # Send my own bridge nick
        self.pushNick(
            cfg.dc_to_irc_bot, "dtbridge", cfg.my_host, "Dtella Bridge")
        self.pushJoin(cfg.dc_to_irc_bot)

        # Give it ops
        self.sendLine(
            ":%s MODE %s +a %s" %
            (cfg.my_host, cfg.irc_chan, cfg.dc_to_irc_bot))

        # Maybe send Dtella nicks
        if osm and osm.syncd:
            self.sendState()

        # Tell the server we're done
        self.sendLine(":%s EOS" % cfg.my_host)


    def handleCmd_EOS(self, prefix, args):

        if prefix != cfg.irc_server:
            return

        print "SYNCD!!!!"

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
        assert (self.readytosend and osm and osm.syncd)

        print "Sending Dtella state to IRC..."

        nicks = osm.nkm.nickmap.values()
        nicks.sort(key=lambda n: n.nick)

        for n in nicks:
            try:
                inick = dc_to_irc(n.nick)

            except NickError, e:
                # Bad nick.  KICK!
                osm = self.main.osm
                chunks = []
                osm.bsm.addKickChunk(
                    chunks, n, cfg.irc_to_dc_bot, str(e), rejoin=False)
                osm.bsm.sendBridgeChange(chunks)

                # Remove from Dtella nick list
                osm.nkm.removeNode(n)
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
                self.ping_dcall = reactor.callLater(30.0, cb)

        self.ping_dcall = reactor.callLater(60.0, cb)


    def updateTopic(self, n, topic):

        osm = self.main.osm
        assert (self.syncd and osm and osm.syncd)

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


    def event_AddNick(self, n):
        try:
            inick = dc_to_irc(n.nick)

        except NickError, e:
            # Bad nick.  KICK!
            osm = self.main.osm
            chunks = []
            osm.bsm.addKickChunk(
                chunks, n, cfg.irc_to_dc_bot, str(e), rejoin=False)
            osm.bsm.sendBridgeChange(chunks)
            raise

        n.inick = inick
        self.main.rdns.addRequest(n)


    def event_RemoveNick(self, n, reason):
        if hasattr(n, 'inick') and not hasattr(n, 'dns_pending'):
            self.pushQuit(n.inick, reason)


    def event_UpdateInfo(self, n):
        pass


    def event_ChatMessage(self, n, nick, text, flags):

        assert not hasattr(n, 'dns_pending')

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

        self.chanbans = {}  # string -> compiled regex


    def addNick(self, nick):
        self.users[nick] = self.User(nick)


    def changeNick(self, oldnick, newnick):
        try:
            u = self.users.pop(oldnick)
        except KeyError:
            print "Nick doesn't exist"
            return

        if newnick in self.users:
            print "New nick already exists!"
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
                    chunks, n, irc_to_dc(l33t), reason
                    )
                osm.bsm.sendBridgeChange(chunks)

                # Forget this nick
                osm.nkm.removeNode(n)
                n.setNoUser()

        try:
            u = self.users[n00b]
        except KeyError:
            print "Nick doesn't exist"
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
                    chunks, n, irc_to_dc(l33t), ("KILL: %s" % reason)
                    )
                osm.bsm.sendBridgeChange(chunks)

                # Forget this nick
                osm.nkm.removeNode(n)
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
            print "already in channel!"
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

        chunks = []

        for c in change:
            if c == '+':
                val = True
            elif c == '-':
                val = False
            elif c == 't':
                ch.topic_locked = val
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
                    self.addChanBan(banmask)
                else:
                    self.chanbans.pop(banmask, None)
                print "bans=", self.chanbans.keys()
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
                    # Skip phantom nicks (i.e. nicks on THIS server)
                    continue

                old_infoindex = self.getInfoIndex(nick)
                u.chanmodes[modeidx] = val
                new_infoindex = self.getInfoIndex(nick)

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


    def addChanBan(self, banmask):
        if banmask in self.chanbans:
            return

        regex_badchars = r".^$+?{}\[]|():"

        ban_re = '^'
        for c in banmask:
            if c == '*':
                ban_re += '.*'
            elif c in regex_badchars:
                ban_re += '\\' + c
            else:
                ban_re += c
        ban_re += '$'

        self.chanbans[banmask] = re.compile(ban_re)


    def nodeBannedInChan(self, n):

        h1 = "%s!dtnode@%s" % (n.inick, n.hostname)
        h2 = "%s!dtnode@%s" % (n.inick, n.hostmask)
        
        for ban_re in self.chanbans.itervalues():
            if ban_re.match(h1) or ban_re.match(h2):
                return True

        return False


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

        # TESTING !!!
        #ip, = struct.unpack('!i', Ad().setTextIP("128.10.0.0").getRawIP())
        #mask = ~0 << 16
        #self.bans = set([(ip, mask)])
        self.bans = set()


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
            osm.mrm.newMessage(''.join(packet), tries=8)

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
        packet.append(struct.pack("!B", dtella_core.PERSIST_BIT))

        chunks = []

        # Add info strings
        self.addInfoChunk(chunks)

        if ircs:
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
        for ip, mask in osm.bsm.bans:
            self.addBanChunk(chunks, ip, mask, True)

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

        assert (osm and osm.syncd)

        packet = osm.mrm.broadcastHeader('BC', osm.me.ipp)
        packet.append(self.nextPktNum())

        chunks = ''.join(chunks)
        packet.append(struct.pack("!H", len(chunks)))
        packet.append(chunks)

        self.signPacket(packet, broadcast=True)

        osm.mrm.newMessage(''.join(packet))


    def sendPrivateBridgeChange(self, n, chunks):

        osm = self.main.osm
        ph = self.main.ph

        assert (osm and osm.syncd)

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


    def addKickChunk(self, chunks, n, l33t, reason,
                     rejoin=True, silent=False):

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


    def nickRemoved(self, n):

        dels = ('dns_pending', 'hostname', 'hostmask', 'inick')

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
            if not (osm and osm.syncd and ircs and ircs.readytosend):
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

#>: NICK {Delta104 1 1171143418 dcg7D5D hawk-****.resnet.purdue.edu irc1.dhirc.com 1 :DCgate-3.2 user
#>: :{Delta104 MODE {Delta104 :+iwx
#>: :{Delta104 SETHOST dh-6626D905.resnet.purdue.edu
#>: :{Delta104 JOIN #dcgate,#dcgate-data


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
        
        self.main.dnsh.ipToHostname(Ad().setRawIP(ip), cb)


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

        if not (ircs and ircs.readytosend):
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
                chunks, n, cfg.irc_to_dc_bot, "Channel Ban", rejoin=True)
            osm.bsm.sendBridgeChange(chunks)

            # Remove from Dtella nick list
            osm.nkm.removeNode(n)
            n.setNoUser()
            return

        inick = n.inick

        ircs.pushNick(inick, "dtnode", hostname, "Dtella %s" % n.dttag[3:])
        ircs.pushMode(inick, "+iwx")
        ircs.pushJoin(inick)

        # Send queued chat messages
        osm.cms.flushQueue(n)


##############################################################################


class DtellaMain_Bridge(dtella_core.DtellaMain_Base):

    def __init__(self):
        dtella_core.DtellaMain_Base.__init__(self)

        # State Manager
        self.state = dtella_state.StateManager(self, 'dtella_bridge.state')
        self.state.persistent = True
        self.state.udp_port = cfg.udp_port
        for addr in cfg.ip_cache:
            self.state.refreshPeer(Ad().setTextIPPort(addr), 0)

        # Peer Handler
        self.ph = BridgeServerProtocol(self)

        # Reverse DNS Manager
        self.rdns = ReverseDNSManager(self)

        # DNS Handler, for performing the actual lookups
        self.dnsh = dtella_dnslookup.DNSHandler(self, cfg.rdns_servers)

        # Bind UDP Port
        try:
            reactor.listenUDP(cfg.udp_port, self.ph)
        except twisted.internet.error.BindError:
            print "Failed to bind UDP port!"
            raise SystemExit

        # IRC Server
        self.ircs = None

        self.startConnecting()


    def cleanupOnExit(self):
        print "Reactor is shutting down.  Doing cleanup."

        self.shutdown(reconnect='no')
        self.state.saveState()

        # Cleanly close the IRC connection before terminating
        if self.ircs:
            return self.ircs.shutdown()


    def connectionPermitted(self):
        return True


    def getBridgeManager(self):
        return {'bsm': BridgeServerManager(self)}


    def logPacket(self, text):
        print "pkt: %s" % text


    def showLoginStatus(self, text, counter=None):
        print text


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

        if self.ircs and self.ircs.readytosend:
            return self.ircs

        return None


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

        # Cancel all the nick-specific state
        if osm:
            for n in self.osm.nodes:
                n.nickRemoved(self)


if __name__ == '__main__':
    
    dtMain = DtellaMain_Bridge()

    ifactory = IRCFactory(dtMain)
    reactor.connectTCP(cfg.irc_server, cfg.irc_port, ifactory)
    reactor.run()


