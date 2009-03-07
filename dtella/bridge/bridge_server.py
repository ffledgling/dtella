"""
Dtella - Bridge Server Module
Copyright (C) 2008  Dtella Labs (http://www.dtella.org/)
Copyright (C) 2008  Paul Marks (http://www.pmarks.net/)
Copyright (C) 2008  Jacob Feisley  (http://www.feisley.com/)

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

from twisted.internet.protocol import ReconnectingClientFactory
from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet import reactor, defer
from twisted.python.runtime import seconds
import twisted.internet.error

from Crypto.Util.number import long_to_bytes
from Crypto.PublicKey import RSA

import time
import struct
import re
import binascii
from collections import deque
from hashlib import md5

import dtella.common.core as core
import dtella.common.state
import dtella.local_config as local
import dtella.bridge.hostmask
from dtella.common.reverse_dns import ipToHostname
from dtella.common.log import LOG

from dtella.common.util import (dcall_discard, dcall_timeleft,
                                validateNick, CHECK)
from dtella.common.core import (Reject, BadPacketError, BadTimingError,
                                NickError)
from dtella.common.ipv4 import Ad
import dtella.common.ipv4 as ipv4

import dtella.bridge_config as cfg

from zope.interface import implements
from zope.interface.verify import verifyClass
from dtella.common.interfaces import IDtellaStateObserver

irc_nick_chars = (
    "-0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
    "abcdefghijklmnopqrstuvwxyz{|}")

escape_chars = """!"#%&'()*+,./:;=?@`~"""
base36_chars = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"

B_USER = "dtbridge"
B_REALNAME = "Dtella Bridge"


class ChannelUserModes(object):
    def __init__(self, *data):
        # *data is be a sequence of (mode, friendly_name, info),
        # in order of decreasing awesomeness.
        #
        # mode is:
        # - A single character, for normal user modes.
        # - ":P", for plain users who have no modes assigned.
        # - ":V" for virtual nicks, not present in the channel.
        #
        # friendly_name is a string used in mode-change messages.
        # info is a DC-formatted info string.
        #
        # All modes must be unique. "" and None must be present.

        # string of mode characters, decreasing in awesomeness.
        self.modes = ""

        # Mapping from 'mode' -> infoindex.
        # Includes ":P" for plain, and ":V" for virtual.
        self.mode_to_index = {}

        self.friendly = []
        self.info = []

        for i, (mode, friendly, info) in enumerate(data):
            if len(mode) == 1:
                # Keep sorted string of normal modes.
                self.modes += mode
            elif mode in (":P", ":V"):
                pass
            else:
                raise ValueError("Invalid mode: " + mode)

            CHECK(mode not in self.mode_to_index)
            self.mode_to_index[mode] = i

            self.friendly.append(friendly)
            self.info.append(info)

        # Make sure plain and virtual were defined.
        CHECK(":P" in self.mode_to_index)
        CHECK(":V" in self.mode_to_index)

    def getJoinedInfo(self):
        return '|'.join(self.info)

    def getUserInfoIndex(self, u):
        # Find the awesomest available mode.
        for m in self.modes:
            if m in u.chanmodes:
                return self.mode_to_index[m]
        # Otherwise, use the plain mode.
        return self.mode_to_index[":P"]

    def getVirtualInfoIndex(self):
        return self.mode_to_index[":V"]


# TODO: it might make sense to move this somewhere non-global.
chan_umodes = ChannelUserModes(
    ("q",  "owner",    "[~] owner$ $IRC\x01$$0$"),
    ("a",  "super-op", "[&] super-op$ $IRC\x01$$0$"),
    ("o",  "op",       "[@] op$ $IRC\x01$$0$"),
    ("h",  "half-op",  "[%] half-op$ $IRC\x01$$0$"),
    ("v",  "voice",    "[+] voice$ $IRC\x01$$0$"),
    (":P", "loser",    "[_]$ $IRC\x01$$0$"),
    (":V", "virtual",  "[>] virtual$ $IRC\x01$$0$"))


class NotOnline(Exception):
    pass


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
    h = binascii.hexlify(md5(ipp).digest())[:6]
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


def matches_dc_to_irc_prefix(nick):
    return nick.lower().startswith(cfg.dc_to_irc_prefix.lower())


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
    if not matches_dc_to_irc_prefix(inick):
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


# Make sure IRC bot has the right prefix.  This will let other bridges
# know we've reserved the prefix, even when no Dtella nicks are online.
CHECK(cfg.dc_to_irc_prefix)
if not cfg.dc_to_irc_bot.startswith(cfg.dc_to_irc_prefix):
    cfg.dc_to_irc_bot = cfg.dc_to_irc_prefix + cfg.dc_to_irc_bot


##############################################################################


class IRCServer(LineOnlyReceiver):
    implements(IDtellaStateObserver)
    showirc = False

    def __init__(self, main):
        self.ism = IRCStateManager(main, self)
        self.server_name = None
        self.shutdown_deferred = None

        self.ping_dcall = None
        self.ping_waiting = False

    def connectionMade(self):
        LOG.info("Connected to IRC server.")
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

        if oldnick:
            self.ism.changeNick(oldnick, newnick)
        else:
            self.ism.addUser(newnick)

    def handleCmd_JOIN(self, prefix, args):
        nick = prefix
        chans = args[0].split(',')

        if cfg.irc_chan in chans:
            self.ism.joinChannel(self.ism.users[nick])

    def handleCmd_PART(self, prefix, args):
        nick = prefix
        chans = args[0].split(',')

        if cfg.irc_chan in chans:
            CHECK(self.ism.partChannel(self.ism.users[nick]))

    def handleCmd_QUIT(self, prefix, args):
        nick = prefix
        self.ism.removeUser(self.ism.users[nick])

    def handleCmd_KICK(self, prefix, args):
        chan = args[0]
        l33t = prefix
        n00b = args[1]
        reason = irc_strip(args[2])

        if chan != cfg.irc_chan:
            return

        if n00b == cfg.dc_to_irc_bot:
            if self.ism.syncd:
                self.pushBotJoin()
            return

        n = self.ism.findDtellaNode(inick=n00b)
        if n:
            self.ism.kickDtellaNode(n, l33t, reason)
        else:
            message = (
                "%s has kicked %s: %s" %
                (irc_to_dc(l33t), irc_to_dc(n00b), reason))
            CHECK(self.ism.partChannel(self.ism.users[n00b], message))

    def handleCmd_KILL(self, prefix, args):
        # :darkhorse KILL }darkhorse :dhirc.com!darkhorse (TEST!!!)
        l33t = prefix
        n00b = args[0]
        reason = irc_strip(args[1])

        if n00b == cfg.dc_to_irc_bot:
            if self.ism.syncd:
                self.pushBotJoin(do_nick=True)
            return

        n = self.ism.findDtellaNode(inick=n00b)
        if n:
            self.ism.kickDtellaNode(n, l33t, reason, is_kill=True)
        else:
            message = (
                "%s has KILL'd %s: %s" %
                (irc_to_dc(l33t), irc_to_dc(n00b), reason))
            self.ism.removeUser(self.ism.users[n00b], message)

    # Treat SVSKILL the same as KILL.
    handleCmd_SVSKILL = handleCmd_KILL

    def handleCmd_TOPIC(self, prefix, args):
        # :Paul TOPIC #dtella Paul 1169420711 :Dtella :: Development Stage
        chan = args[0]
        whoset = args[1]
        text = irc_strip(args[-1])

        if chan == cfg.irc_chan:
            self.ism.setTopic(whoset, text)

    def handleCmd_MODE(self, prefix, args):
        # :Paul MODE #dtella +vv aaahhh Big_Guy
        whoset = prefix
        chan = args[0]
        change = args[1]
        nicks = args[2:]

        if chan != cfg.irc_chan:
            return

        on_off = True
        i = 0

        # User() -> {mode -> on_off}
        user_changes = {}

        # Dtella node modes that need unsetting.
        unset_modes = []
        unset_nicks = []

        for c in change:
            if c == '+':
                on_off = True
            elif c == '-':
                on_off = False
            elif c == 't':
                self.ism.setTopicLocked(whoset, on_off)
            elif c == 'm':
                self.ism.setModerated(whoset, on_off)
            elif c == 'k':
                # Skip over channel key
                i += 1
            elif c == 'l':
                # Skip over channel user limit
                i += 1
            elif c == 'b':
                banmask = nicks[i]
                i += 1
                self.ism.setChannelBan(whoset, on_off, banmask)
            elif c in chan_umodes.modes:
                # Grab affected nick
                nick = nicks[i]
                i += 1

                n = self.ism.findDtellaNode(inick=nick)
                if n:
                    # If someone set a mode for a Dt node, unset it.
                    if on_off:
                        unset_modes.append(c)
                        unset_nicks.append(nick)
                    continue

                # Get the IRC user we're modifying.
                try:
                    u = self.ism.users[nick]
                except KeyError:
                    LOG.error("MODE: unknown nick: %s" % nick)
                    continue

                # Schedule a mode change for this user.
                user_changes.setdefault(u, {})[c] = on_off

        # Undo mode changes for Dtella nodes.
        if unset_modes:
            self.sendLine(
                ":%s MODE %s -%s %s" % (
                    cfg.dc_to_irc_bot, cfg.irc_chan,
                    ''.join(unset_modes), ' '.join(unset_nicks)))

        # Send IRC user mode changes to Dtella
        for u, changes in user_changes.iteritems():
            self.ism.setChannelUserModes(whoset, u, changes)

    def handleCmd_TKL(self, prefix, args):
        addrem = args[0]
        kind = args[1]

        if addrem == '+':
            on_off = True
        elif addrem == '-':
            on_off = False
        else:
            LOG.error("TKL: invalid modifier: '%s'" % addrem)
            return

        # :irc1.dhirc.com TKL + Z * 128.10.12.0/24 darkhorse!admin@dhirc.com 0 1171427130 :no reason
        if kind == 'Z' and args[2] == '*':
            cidr = args[3]
            self.ism.setNetworkBan(cidr, on_off)

        # :%s TKL + Q * %s* %s 0 %d :Reserved for Dtella
        elif kind == 'Q':
            nickmask = args[3]
            if on_off:
                reason = args[-1]
                self.ism.addQLine(nickmask, reason)
            else:
                self.ism.removeQLine(nickmask)

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

        LOG.info("IRC Server Name: %s" % self.server_name)

        # Tell the ReconnectingClientFactory that we're cool
        self.factory.resetDelay()

        # This isn't very correct, because the Dtella nicks
        # haven't been sent yet, but it's the best we can practically do.
        cloak_checksum = dtella.bridge.hostmask.get_checksum()
        self.sendLine("NETINFO 0 %d 0 %s 0 0 0 :%s" %
                      (time.time(), cloak_checksum, cfg.irc_network_name))
        self.sendLine(":%s EOS" % cfg.my_host)

    def handleCmd_EOS(self, prefix, args):
        if prefix != self.server_name:
            return
        if self.ism.syncd:
            return

        LOG.info("Finished receiving IRC sync data.")

        self.showirc = True

        # Check for conflicting bridges.
        if self.ism.findConflictingBridge():
            LOG.error("My nick prefix is in use! Terminating.")
            self.transport.loseConnection()
            reactor.stop()
            return

        # Set up nick reservation
        self.sendLine(
            "TKL + Q * %s* %s 0 %d :Reserved for Dtella" %
            (cfg.dc_to_irc_prefix, cfg.my_host, time.time()))
        self.ism.killConflictingUsers()

        # Send my own bridge nick
        self.pushBotJoin(do_nick=True)

        # When we enter the syncd state, register this instance with Dtella.
        # This will eventually trigger event_DtellaUp, where we send our state.
        self.schedulePing()
        self.ism.addMeToMain()

    def handleCmd_WHOIS(self, prefix, args):
        # Somewhat simplistic handling of WHOIS requests
        if not (prefix and len(args) >= 1):
            return

        src = prefix
        who = args[-1]

        if who == cfg.dc_to_irc_bot:
            self.pushWhoisReply(
                311, src, who, B_USER, cfg.my_host, '*', B_REALNAME)
            self.pushWhoisReply(
                312, src, who, cfg.my_host, cfg.my_name)
            self.pushWhoisReply(
                319, src, who, cfg.irc_chan)
        else:
            n = self.ism.findDtellaNode(inick=who)
            if not (n and hasattr(n, 'hostmask')):
                return

            self.pushWhoisReply(
                311, src, who, n_user(n.ipp), n.hostmask, '*',
                "Dtella %s" % n.dttag[3:])
            self.pushWhoisReply(
                312, src, who, cfg.my_host, cfg.my_name)
            self.pushWhoisReply(
                319, src, who, cfg.irc_chan)

            if local.use_locations:
                self.pushWhoisReply(
                    320, src, who, "Location: %s"
                    % local.hostnameToLocation(n.hostname))

        self.pushWhoisReply(
            318, src, who, "End of /WHOIS list.")

    def pushWhoisReply(self, code, target, who, *strings):
        line = ":%s %d %s %s " % (cfg.my_host, code, target, who)
        strings = list(strings)
        strings[-1] = ":" + strings[-1]
        line += ' '.join(strings)
        self.sendLine(line)

    def handleCmd_PRIVMSG(self, prefix, args):
        src_nick = prefix
        target = args[0]
        text = args[1]
        flags = 0

        if (text[:8], text[-1:]) == ('\001ACTION ', '\001'):
            text = text[8:-1]
            flags |= core.SLASHME_BIT

        text = irc_strip(text)

        if target == cfg.irc_chan:
            self.ism.sendChannelMessage(src_nick, text, flags)
	
        #Format> :Global PRIVMSG $irc3.dhirc.com :TESTING....
        #Handle global messages delivered to the bridge.
        elif target == "$" + cfg.my_host:
            flags |= core.NOTICE_BIT
            self.ism.sendChannelMessage(src_nick, text, flags)

        else:
            n = self.ism.findDtellaNode(inick=target)
            if n:
                self.ism.sendPrivateMessage(n, src_nick, text, flags)

    def handleCmd_NOTICE(self, prefix, args):
        src_nick = prefix
        target = args[0]
        text = irc_strip(args[1])
        flags = core.NOTICE_BIT

        if target == cfg.irc_chan:
            self.ism.sendChannelMessage(src_nick, text, flags)
        else:
            n = self.ism.findDtellaNode(inick=target)
            if n:
                self.ism.sendPrivateMessage(n, src_nick, text, flags)

    def pushNick(self, nick, user, host, modes, ip, name):
        # If an IP was provided, convert to a base64 parameter.
        if ip:
            ip = ' ' + binascii.b2a_base64(ip).rstrip()
        else:
            ip = ''

        self.sendLine(
            "NICK %s 1 %d %s %s %s 1 %s *%s :%s" %
            (nick, time.time(), user, host, cfg.my_host, modes, ip, name))

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
                cfg.dc_to_irc_bot, B_USER, cfg.my_host, "+Sq", None,
                B_REALNAME)

        # Join channel, and grant ops.
        self.pushJoin(cfg.dc_to_irc_bot)
        self.sendLine(
            ":%s MODE %s +ao %s %s" %
            (cfg.my_host, cfg.irc_chan, cfg.dc_to_irc_bot, cfg.dc_to_irc_bot))

    def pushKill(self, nick):
        LOG.info("Killing nick: " + nick)
        self.sendLine(":%s KILL %s :%s (nick reserved for Dtella)"
                      % (cfg.my_host, nick, cfg.my_host))

    def pushRemoveQLine(self, nickmask):
        LOG.info("Telling network to remove Q-line: %s" % nickmask)
        self.sendLine("TKL - Q * %s %s" % (nickmask, cfg.my_host))

    def schedulePing(self):
        if self.ping_dcall:
            self.ping_dcall.reset(60.0)
            return

        def cb():
            self.ping_dcall = None

            if self.ping_waiting:
                LOG.error("Ping timeout!")
                self.transport.loseConnection()
            else:
                self.sendLine("PING :%s" % cfg.my_host)
                self.ping_waiting = True
                self.ping_dcall = reactor.callLater(60.0, cb)

        self.ping_dcall = reactor.callLater(60.0, cb)

    def shutdown(self):
        if self.shutdown_deferred:
            return self.shutdown_deferred

        # Remove nick ban
        self.pushRemoveQLine(cfg.dc_to_irc_prefix + "*")

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
        LOG.info("Lost IRC connection.")
        if self.ism.syncd:
            self.ism.removeMeFromMain()

        if self.shutdown_deferred:
            self.shutdown_deferred.callback("Bye!")

##############################################################################

class User(object):
    def __init__(self, inick):
        self.inick = inick

        # This user's single-character channel modes.
        self.chanmodes = set()

    def __repr__(self):
        return "User(%r)" % self.inick


class IRCStateManager(object):
    implements(IDtellaStateObserver)

    def __init__(self, main, ircs=None):
        self.main = main
        self.ircs = ircs
        self.syncd = False

        # dnick -> User()
        self.users = {}

        # Set of all User()s in the Dtella channel.
        self.chanusers = set()

        self.topic = ""
        self.topic_whoset = ""  # always a dnick
        self.topic_locked = False

        self.moderated = False

        # string -> compiled regex
        self.chanbans = {}
        # string -> compiled regex
        self.qlines = {}

        # Network bans: (ip, mask), both ints.
        self.bans = set()

    # --- These methods are called from the IRC server ---
    def addMeToMain(self):
        CHECK(not self.syncd)
        self.syncd = True
        self.main.addIRCStateManager(self)

    def removeMeFromMain(self):
        self.main.removeIRCStateManager(self)

    def addUser(self, inick):
        # Start tracking a new IRC user.
        if inick in self.users:
            LOG.error("addUser: '%s' already exists." % inick)
            return

        # Don't allow nicks which match my prefix.
        if self.syncd and matches_dc_to_irc_prefix(inick):
            if self.ircs:
                self.ircs.pushKill(inick)
            return

        self.users[inick] = u = User(inick)

    def removeUser(self, u, message=None):
        self.partChannel(u, message)
        if self.users.pop(u.inick, None) != u:
            LOG.error("removeUser: %r not found" % u)
            return

    def changeNick(self, old_inick, new_inick):
        # If the destination nick already exists, then our state must be
        # somehow corrupted.  Oh well, just assume the server knows what
        # it's talking about, and throw away the existing user.
        try:
            dest_u = self.users.pop(new_inick)
        except KeyError:
            pass
        else:
            LOG.error("changeNick '%s'->'%s': Dest nick already exists."
                      % (old_inick, new_inick))
            self.chanusers.discard(dest_u)

        # Now find the source user.
        try:
            u = self.users.pop(old_inick)
        except KeyError:
            LOG.error("changeNick '%s'->'%s': Source nick not found."
                      % (old_inick, new_inick))
            return

        # Don't allow IRC nicks which match my prefix.
        if self.syncd and matches_dc_to_irc_prefix(new_inick):
            if self.ircs:
                self.ircs.pushKill(new_inick)
            self.partChannel(u)
            return

        u.inick = new_inick
        self.users[new_inick] = u

        # Report the change to Dtella.
        if u in self.chanusers:
            try:
                osm = self.getOnlineStateManager()
            except NotOnline:
                return

            infoindex = chan_umodes.getUserInfoIndex(u)

            chunks = []
            osm.bsm.addChatChunk(
                chunks, cfg.irc_to_dc_bot,
                "%s is now known as %s" % (irc_to_dc(old_inick),
                                           irc_to_dc(new_inick))
                )
            osm.bsm.addNickChunk(
                chunks, irc_to_dc(old_inick), 0xFF)
            osm.bsm.addNickChunk(
                chunks, irc_to_dc(new_inick), infoindex)
            osm.bsm.sendBridgeChange(chunks)

    def joinChannel(self, u):
        if u in self.chanusers:
            LOG.error("joinChannel: %r already in channel." % u)
            return

        self.chanusers.add(u)
        u.chanmodes.clear()

        try:
            osm = self.getOnlineStateManager()
        except NotOnline:
            return

        infoindex = chan_umodes.getUserInfoIndex(u)
        chunks = []
        osm.bsm.addNickChunk(
            chunks, irc_to_dc(u.inick), infoindex)
        osm.bsm.sendBridgeChange(chunks)

    def partChannel(self, u, message=None):
        # Remove user from the Dtella channel. Return True if successful.
        try:
            self.chanusers.remove(u)
        except KeyError:
            return False

        try:
            osm = self.getOnlineStateManager()
        except NotOnline:
            return False

        chunks = []
        if message:
            osm.bsm.addChatChunk(chunks, cfg.irc_to_dc_bot, message)
        osm.bsm.addNickChunk(chunks, irc_to_dc(u.inick), 0xFF)
        osm.bsm.sendBridgeChange(chunks)
        return True

    def findDtellaNode(self, inick=None, dnick=None):
        # Try to find a user on Dtella.
        if inick:
            try:
                dnick = dc_from_irc(inick)
            except NickError:
                pass
        if not dnick:
            return None

        try:
            osm = self.getOnlineStateManager()
            return osm.nkm.lookupNick(dnick)
        except (NotOnline, KeyError):
            return None

    def kickDtellaNode(self, n, l33t_inick, reason, is_kill=False):
        # Handler for KICK/KILL of an existing Dtella user.
        # Caller should get 'n' from findDtellaNode()

        # Exception shouldn't happen here; don't catch.
        osm = self.getOnlineStateManager()

        if is_kill:
            reason = "KILL: " + reason

        # Send a kick message.
        chunks = []
        osm.bsm.addKickChunk(
            chunks, n, irc_to_dc(l33t_inick), reason,
            rejoin=True, silent=False
            )
        osm.bsm.sendBridgeChange(chunks)

        # Forget this nick.
        if is_kill:
            del n.inick
        osm.nkm.removeNode(n, "Kicked")
        n.setNoUser()

    def sendPrivateMessage(self, n, src_inick, text, flags):
        # Send a private message to a Dtella node.
        # Caller should get 'n' from findDtellaNode()

        # Exception shouldn't happen here; don't catch.
        osm = self.getOnlineStateManager()

        chunks = []
        osm.bsm.addMessageChunk(
            chunks, irc_to_dc(src_inick), text, flags)
        osm.bsm.sendPrivateBridgeChange(n, chunks)

    def sendChannelMessage(self, src_inick, text, flags):
        # Send text to all Dtella nodes.
        try:
            osm = self.getOnlineStateManager()
        except NotOnline:
            return

        chunks = []
        osm.bsm.addChatChunk(
            chunks, irc_to_dc(src_inick), text, flags)
        osm.bsm.sendBridgeChange(chunks)

    def setTopic(self, whoset, topic):
        try:
            # DC nick
            dnick = dc_from_irc(whoset)
        except NickError:
            # IRC nick
            dnick = irc_to_dc(whoset)

        self.topic = topic
        self.topic_whoset = dnick

        try:
            osm = self.getOnlineStateManager()
        except NotOnline:
            return

        chunks = []
        osm.bsm.addTopicChunk(
            chunks, dnick, topic, changed=True)
        osm.bsm.sendBridgeChange(chunks)

    def setModerated(self, whoset, on_off):
        self.moderated = on_off
        try:
            osm = self.getOnlineStateManager()
        except NotOnline:
            return

        if on_off:
            action = "enabled"
        else:
            action = "disabled"

        chunks = []
        osm.bsm.addModeratedChunk(chunks, on_off)
        osm.bsm.addChatChunk(
            chunks, cfg.irc_to_dc_bot,
            "%s %s moderation." % (irc_to_dc(whoset), action))
        osm.bsm.sendBridgeChange(chunks)

    def setTopicLocked(self, whoset, on_off):
        self.topic_locked = on_off
        try:
            osm = self.getOnlineStateManager()
        except NotOnline:
            return

        if on_off:
            action = "locked"
        else:
            action = "unlocked"

        chunks = []
        osm.bsm.addChatChunk(
            chunks, cfg.irc_to_dc_bot,
            "%s %s the topic." % (irc_to_dc(whoset), action))
        osm.bsm.sendBridgeChange(chunks)

    def setChannelBan(self, whoset, on_off, banmask):
        if on_off:
            self.chanbans[banmask] = wild_to_regex(banmask)
            action = "added"
        else:
            self.chanbans.pop(banmask, None)
            action = "removed"
        LOG.debug( "bans= %s" % self.chanbans.keys() )

        try:
            osm = self.getOnlineStateManager()
        except NotOnline:
            return

        chunks = []
        osm.bsm.addChatChunk(
            chunks, cfg.irc_to_dc_bot,
            "%s %s ban: %s" % (irc_to_dc(whoset), action, banmask))
        osm.bsm.sendBridgeChange(chunks)

    def setChannelUserModes(self, whoset, u, changes):
        # changes: dict of {mode -> on_off}
        if u not in self.chanusers:
            LOG.error("setChannelUserModes: %r not in channel." % u)
            return

        # Save old index, apply changes, and get new index.
        old_infoindex = chan_umodes.getUserInfoIndex(u)
        for mode, on_off in changes.iteritems():
            if on_off:
                u.chanmodes.add(mode)
            else:
                u.chanmodes.discard(mode)
        new_infoindex = chan_umodes.getUserInfoIndex(u)

        if new_infoindex == old_infoindex:
            # Change isn't relevant to Dtella; ignore.
            return

        try:
            osm = self.getOnlineStateManager()
        except NotOnline:
            return

        chunks = []
        osm.bsm.addNickChunk(
            chunks, irc_to_dc(u.inick), new_infoindex)
        osm.bsm.addChatChunk(
            chunks, cfg.irc_to_dc_bot,
            "%s changed mode for %s: %s -> %s" % (
                irc_to_dc(whoset),
                irc_to_dc(u.inick),
                chan_umodes.friendly[old_infoindex],
                chan_umodes.friendly[new_infoindex]))
        osm.bsm.sendBridgeChange(chunks)

    def addQLine(self, nickmask, reason):
        nick_re = wild_to_regex(nickmask)

        # After EOS, auto-remove any Q-lines which conflict with mine.
        # This may cause a conflicting bridge to abort.
        if self.syncd and nick_re.match(cfg.dc_to_irc_prefix):
            if self.ircs:
                self.ircs.pushRemoveQLine(nickmask)
            LOG.info("Conflicted Q-line: " + nickmask)
            return

        self.qlines[nickmask] = (nick_re, reason)
        LOG.info("Added Q-line: " + nickmask)

    def removeQLine(self, nickmask):
        self.qlines.pop(nickmask, None)
        LOG.info("Removed Q-line: " + nickmask)

        # If some other bridge removes our reservation, abort.
        if self.syncd and (nickmask == cfg.dc_to_irc_prefix + "*"):
            LOG.error("My own Q-line was removed! Terminating.")
            if self.ircs:
                self.ircs.transport.loseConnection()
            reactor.stop()

    def setNetworkBan(self, cidr, on_off):
        # See if this is a valid 1.2.3.4/5 CIDR string.
        try:
            ipmask = ipv4.CidrStringToIPMask(cidr)
        except ValueError, e:
            LOG.error("Bad CIDR string: %s")
            return

        # Convert back, to get a normalized string.
        cidr = ipv4.IPMaskToCidrString(ipmask)

        if on_off:
            if ipmask in self.bans:
                LOG.warning("Duplicate ban: %s" % cidr)
                return
            self.bans.add(ipmask)
            LOG.info("Added ban: %s" % cidr)
        else:
            try:
                self.bans.remove(ipmask)
            except KeyError:
                LOG.warning("Ban not found: %s" % cidr)
                return
            LOG.info("Removed ban: %s" % cidr)

        # If we're online, broadcast the ban.
        try:
            osm = self.getOnlineStateManager()
        except NotOnline:
            pass
        else:
            ip, mask = ipmask
            chunks = []
            osm.bsm.addBanChunk(chunks, ip, mask, on_off)
            osm.bsm.sendBridgeChange(chunks)

        # If we're even sort-of online, update local bans.
        if self.main.osm:
            self.main.osm.banm.scheduleRebuildBans()

    def findConflictingBridge(self):
        # Determine if another bridge conflicts with me.
        # Return True if we need to abort.
        CHECK(self.ircs and not self.syncd)

        stale_qlines = []
        for nickmask, (q, reason) in self.qlines.iteritems():
            # Look for Q-lines which conflict with my prefix.
            if not q.match(cfg.dc_to_irc_prefix):
                continue
            LOG.info("Found a conflicting Q-line: %s" % nickmask)

            # If any nicks exist under that Q-line, we'll need to abort.
            for nick in self.users:
                if q.match(nick):
                    LOG.info("... and a nick to go with it: %s" % nick)
                    return True

            stale_qlines.append(nickmask)

        # Remove all stale Q-lines from the network.
        LOG.info("Stale qlines: %r" % stale_qlines)
        for nickmask in stale_qlines:
            del self.qlines[nickmask]
            self.ircs.pushRemoveQLine(nickmask)

        # Conflict has been neutralized.
        return False

    def killConflictingUsers(self):
        # Find any reserved nicks, and KILL them.
        CHECK(self.ircs and not self.syncd)
        bad_users = [u for u in self.users.itervalues()
                     if matches_dc_to_irc_prefix(u.inick)]
        LOG.info("Conflicting users: %r" % bad_users)
        for u in bad_users:
            self.ircs.pushKill(u.inick)
            self.removeUser(u)

    # --- These methods are used by the rest of Dtella ---
    def isNodeChannelBanned(self, n):
        h1 = "%s!%s@%s" % (n.inick, n_user(n.ipp), n.hostname)
        h2 = "%s!%s@%s" % (n.inick, n_user(n.ipp), n.hostmask)

        for ban_re in self.chanbans.itervalues():
            if ban_re.match(h1) or ban_re.match(h2):
                return True

        return False

    def getNicksAndInfo(self):
        # Return (dnick, infoindex) for all users.
        nicks = []

        for u in self.chanusers:
            nicks.append(
                (irc_to_dc(u.inick), chan_umodes.getUserInfoIndex(u)))

        for inick in cfg.virtual_nicks:
            nicks.append(
                (irc_to_dc(inick), chan_umodes.getVirtualInfoIndex()))

        nicks.sort()
        return nicks

    def bridgeevent_TopicChange(self, n, topic):
        # Topic change, from a Dtella node.
        # Return True if successful.
        CHECK(self.syncd)

        if self.topic_locked:
            return False

        if self.ircs:
            self.ircs.pushTopic(n.inick, topic)

        self.setTopic(n.inick, topic)
        return True

    def bridgeevent_PrivMsg(self, n, dst_inick, text):
        # Send a private message from Dtella to IRC.
        # Return True if successful.
        CHECK(self.syncd)

        try:
            u = self.users[dst_inick]
        except KeyError:
            return False

        if self.ircs:
            self.ircs.pushPrivMsg(n.inick, text, dst_inick)
            return True

        return False

    def event_AddNick(self, n):
        # Might raise NickError
        inick = self.checkIncomingNick(n)

        # The inick attribute gets dropped during a KILL, so
        # event_RemoveNick won't try to send a stale QUIT.
        n.inick = inick

        self.main.rdns.addRequest(n)

    def event_RemoveNick(self, n, reason):
        try:
            inick = n.inick
            del n.inick
        except AttributeError:
            # Node has already been dropped from IRC.
            return

        if hasattr(n, 'dns_pending'):
            # Node never made it to IRC.
            return

        if self.ircs:
            self.ircs.pushQuit(inick, reason)

    def event_UpdateInfo(self, n):
        pass

    def event_ChatMessage(self, n, nick, text, flags):
        CHECK(not hasattr(n, 'dns_pending'))

        if not self.ircs:
            return

        if flags & core.NOTICE_BIT:
            self.ircs.pushNotice(n.inick, text)
        elif flags & core.SLASHME_BIT:
            self.ircs.pushPrivMsg(n.inick, text, action=True)
        else:
            self.ircs.pushPrivMsg(n.inick, text)

    def event_DtellaUp(self):
        osm = self.getOnlineStateManager()

        LOG.info("Sending Dtella state to IRC...")

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

    def event_DtellaDown(self):
        if self.ircs:
            self.ircs.pushPrivMsg(
                cfg.dc_to_irc_bot, "Bridge lost connection to Dtella")

    def event_KickMe(self, lines, rejoin_time):
        raise NotImplemented("Bridge can't be kicked.")

    def shutdown(self):
        if self.ircs:
            return self.ircs.shutdown()

    # --- These methods are internal ---
    def getOnlineStateManager(self):
        # Internal method; Get the OSM if we're fully syncd.
        osm = self.main.osm
        if (self.syncd and osm and osm.syncd):
            return osm

        # Not online; caller is expected to catch this.
        raise NotOnline

    def checkIncomingNick(self, n):
        # Validate new nicks as they join.
        # If successful, return inick, else raise NickError.
        try:
            inick = dc_to_irc(n.nick)

            if inick.lower() == cfg.dc_to_irc_bot.lower():
                raise NickError("Nick '%s' conflicts with IRC bot." % inick)

            for q, reason in self.qlines.itervalues():
                if q.match(inick):
                    raise NickError(
                        "Nick '%s' is Q-lined: %s" % (inick, reason))

        except NickError, e:
            LOG.debug("Bad nick: %s %s" % (n.nick, str(e)))
            # Bad nick.  KICK!

            osm = self.main.osm
            chunks = []
            osm.bsm.addKickChunk(
                chunks, n, cfg.irc_to_dc_bot, str(e),
                rejoin=False, silent=True)
            osm.bsm.sendBridgeChange(chunks)
            raise

        return inick

verifyClass(IDtellaStateObserver, IRCStateManager)

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

class BridgeServerProtocol(core.PeerHandler):

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
            raise BadTimingError("Not ready for bQ")

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
        ism = self.main.ism
        return (ism and ism.moderated)

    def nextPktNum(self):
        t = long(time.time())
        if self.bridge_pktnum >> 24 == t:
            self.bridge_pktnum += 1
        else:
            self.bridge_pktnum = (t << 24L)

        return struct.pack("!Q", self.bridge_pktnum)

    def syncComplete(self):
        # This is called from OnlineStateManager after the Dtella network
        # is fully syncd.
        osm = self.main.osm

        # Splice in some handlers
        osm.yqrm.sendSyncReply = self.sendSyncReply
        osm.makeExitPacket = self.makeExitPacket

    def signPacket(self, packet, broadcast):
        data = ''.join(packet)

        if broadcast:
            body = data[0:2] + data[10:]
        else:
            body = data

        data_hash = md5(body).digest()

        t = time.time()
        sig, = self.rsa_obj.sign(data_hash, None)
        LOG.debug("Sign Time = %f sec" % (time.time() - t))

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

        # The first time, send state immediately.
        cb()

    def getStateData(self, packet):
        # All the state info common between BS and Br packets

        osm = self.main.osm
        CHECK(osm and osm.syncd)

        # Get the IRC Server, if it's ready
        ism = self.main.ism

        # Sequence number
        packet.append(self.nextPktNum())

        # Expiration time
        when = int(dcall_timeleft(self.sendState_dcall))
        packet.append(struct.pack("!H", when))

        # Session ID, uptime flags
        packet.append(osm.me.sesid)
        packet.append(struct.pack("!I", int(seconds() - osm.me.uptime)))
        packet.append(struct.pack("!B", core.PERSIST_BIT))

        chunks = []

        # Add info strings
        self.addInfoChunk(chunks)

        if ism:
            # Add the list of online nicks
            for dnick, infoindex in ism.getNicksAndInfo():
                self.addNickChunk(chunks, dnick, infoindex)

            self.addTopicChunk(
                chunks, ism.topic_whoset, ism.topic, changed=False)

            # Get bans list
            for ip, mask in ism.bans:
                self.addBanChunk(chunks, ip, mask, True)

            if ism.moderated:
                self.addModeratedChunk(chunks, True)

        chunks = ''.join(chunks)

        # Split data string into 1k blocks
        blocks = []
        for i in range(0, len(chunks), 1024):
            blocks.append(chunks[i:i+1024])

        block_hashes = [md5(b).digest() for b in blocks]

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
            LOG.debug("bC failed: %s" % detail)

        n.sendPrivateMessage(ph, ack_key, packet, fail_cb)

    def addNickChunk(self, chunks, nick, mode):
        chunks.append('N')
        chunks.append(struct.pack("!BB", mode, len(nick)))
        chunks.append(nick)

    def addInfoChunk(self, chunks):
        chunks.append('I')
        joined_info = chan_umodes.getJoinedInfo()
        chunks.append(struct.pack("!H", len(joined_info)))
        chunks.append(joined_info)

    def addKickChunk(self, chunks, n, l33t, reason, rejoin, silent):
        # Pick a packet number that's a little bit ahead of what the node
        # is using, so that any status messages sent out by the node at
        # the same time will be overriden by the kick.

        n.status_pktnum = (n.status_pktnum + 3) % 0x100000000

        flags = (rejoin and core.REJOIN_BIT)

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
        subnet = ipv4.MaskToCidrNum(mask)
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
        flags = (changed and core.CHANGE_BIT)

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
        flags = (enable and core.MODERATED_BIT)
        chunks.append('F')
        chunks.append(struct.pack('!B', flags))

    def receivedBlockRequest(self, src_ipp, bhash):
        try:
            b = self.cached_blocks[bhash]
        except KeyError:
            LOG.warning("Requested block not found")
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
        ism = self.main.ism

        ack_flags = 0

        try:
            if not (osm and osm.syncd and ism):
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
                    dst_inick = irc_from_dc(dst_nick)
                except NickError:
                    raise Reject("Invalid dest nick")

                if not ism.bridgeevent_PrivMsg(n, dst_inick, text):
                    raise Reject("Dest not on IRC")

        except Reject:
            ack_flags |= core.ACK_REJECT_BIT

        self.main.ph.sendAckPacket(src_ipp, core.ACK_PRIVATE,
                                   ack_flags, ack_key)

    def receivedTopicChange(self, src_ipp, ack_key, src_nhash, topic):
        osm = self.main.osm
        ism = self.main.ism

        ack_flags = 0

        try:
            if not (osm and osm.syncd and ism):
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

                if not ism.bridgeevent_TopicChange(n, topic):
                    raise Reject("Topic locked")

        except Reject:
            ack_flags |= core.ACK_REJECT_BIT

        self.main.ph.sendAckPacket(
            src_ipp, core.ACK_PRIVATE, ack_flags, ack_key)

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

        LOG.debug("Querying %s" % Ad().setRawIP(ip).getTextIP())
        ipToHostname(Ad().setRawIP(ip)).addCallback(cb)

    def signOn(self, ipp, hostname):
        osm = self.main.osm
        ism = self.main.ism

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

        if not ism:
            return

        if hostname is None:
            hostname = Ad().setRawIPPort(ipp).getTextIP()
            hostmask = dtella.bridge.hostmask.mask_ipv4(hostname)
        else:
            hostmask = dtella.bridge.hostmask.mask_hostname(hostname)

        n.hostname = hostname
        n.hostmask = hostmask

        # Check channel ban
        if ism.isNodeChannelBanned(n):
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

        if ism.ircs:
            ism.ircs.pushNick(
                n.inick, n_user(n.ipp), hostname, "+iwx", n.ipp[:4],
                "Dtella %s" % n.dttag[3:])
            ism.ircs.pushJoin(n.inick)

        # Send queued chat messages
        osm.cms.flushQueue(n)
