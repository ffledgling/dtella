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
    "\x03[0-9]{1,2}(,[0-9]{1,2})?|[\x00-\x1F]")

def irc_strip(text):
    return ircstrip_re.sub('', text)


# Make sure IRC bot has the right prefix.  This will let other bridges
# know we've reserved the prefix, even when no Dtella nicks are online.
CHECK(cfg.dc_to_irc_prefix)
if not cfg.dc_to_irc_bot.startswith(cfg.dc_to_irc_prefix):
    cfg.dc_to_irc_bot = cfg.dc_to_irc_prefix + cfg.dc_to_irc_bot


##############################################################################


# Set up service config (IRC, etc.)
def newServiceConfig():
    try:
        service_class = cfg.service_class
        service_args = cfg.service_args
    except AttributeError:
        # For backwards compatibility, use Unreal by default.
        service_class = "dtella.bridge.unreal.UnrealConfig"
        service_args = dict(
            host = cfg.irc_server,
            port = cfg.irc_port,
            ssl = cfg.irc_ssl,
            password = cfg.irc_password,
            network_name = cfg.irc_network_name,
            my_host = cfg.my_host,
            my_name = cfg.my_name,
            channel = cfg.irc_chan,
            hostmask_prefix = cfg.hostmask_prefix,
            hostmask_keys = cfg.hostmask_keys,
            )

    # The class name is defined as a string in cfg, to prevent problems
    # with import cycles.

    # "foo.bar.Baz" -> ("foo.bar", "Baz")
    try:
        mod, cls = service_class.rsplit(".", 1)
        ConfigClass = getattr(__import__(mod, globals(), locals(), [cls]), cls)
    except Exception, e:
        raise ImportError("Failed to locate cfg.service_class (%r): %s"
                          % (service_class, e))
    return ConfigClass(**service_args)


def getServiceConfig():
    # Get the service config, creating it on first use.
    global _scfg
    try:
        return _scfg
    except NameError:
        _scfg = newServiceConfig()
        return _scfg


##############################################################################


class ChannelUserModes(object):
    def __init__(self, *data):
        # *data is a sequence of (mode, symbol, friendly_name, info),
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

        # Mapping from @%+-ish symbol to "ohv" mode.
        self.symbol_to_mode = {}

        self.friendly = []
        self.info = []

        for i, (mode, symbol, friendly, info) in enumerate(data):
            if len(mode) == 1:
                # Keep sorted string of normal modes.
                self.modes += mode
            elif mode in (":P", ":V"):
                CHECK(not symbol)
            else:
                raise ValueError("Invalid mode: " + mode)

            CHECK(mode not in self.mode_to_index)
            self.mode_to_index[mode] = i

            if symbol:
                self.symbol_to_mode[symbol] = mode

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


class NotOnline(Exception):
    pass


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

        # inick.lower() -> User object
        self.users = {}

        # Set of all User()s in the Dtella channel.
        self.chanusers = set()

        self.topic = ""
        self.topic_whoset = ""  # always a dnick
        self.topic_locked = False

        self.moderated = False

        # string -> compiled regex
        self.chanbans = {}
        # string -> (compiled regex, reason)
        self.qlines = {}

        # Network bans: (ip, mask), both ints.
        self.bans = set()

    # --- These methods are called from the IRC server ---
    def addMeToMain(self):
        CHECK(not self.syncd)
        self.syncd = True
        self.main.addIRCStateManager(self)

    def removeMeFromMain(self):
        # After calling this, I'm basically a dead object.
        self.main.removeIRCStateManager(self)

    def addUser(self, inick):
        # Start tracking a new IRC user.
        if inick.lower() in self.users:
            LOG.error("addUser: '%s' already exists." % inick)
            return

        # Don't allow nicks which match my prefix.
        if self.syncd and matches_dc_to_irc_prefix(inick):
            if self.ircs:
                self.ircs.pushKill(inick)
            return

        self.users[inick.lower()] = u = User(inick)

    def removeUser(self, u, message=None):
        self.partChannel(u, message)
        if self.users.pop(u.inick.lower(), None) != u:
            LOG.error("removeUser: %r not found" % u)
            return

    def findUser(self, inick):
        return self.users[inick.lower()]

    def changeNick(self, old_inick, new_inick):
        if old_inick.lower() == new_inick.lower():
            LOG.error("changeNick '%s'->'%s': Nicks are equivalent."
                      % (old_inick, new_inick))
            return

        # If the destination nick already exists, then our state must be
        # somehow corrupted.  Oh well, just assume the server knows what
        # it's talking about, and throw away the existing user.
        try:
            dest_u = self.users.pop(new_inick.lower())
        except KeyError:
            pass
        else:
            LOG.error("changeNick '%s'->'%s': Dest nick already exists."
                      % (old_inick, new_inick))
            self.chanusers.discard(dest_u)

        # Now find the source user.
        try:
            u = self.users.pop(old_inick.lower())
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
        self.users[new_inick.lower()] = u

        scfg = getServiceConfig()

        # Report the change to Dtella.
        if u in self.chanusers:
            try:
                osm = self.getOnlineStateManager()
            except NotOnline:
                return

            infoindex = scfg.chan_umodes.getUserInfoIndex(u)

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

        scfg = getServiceConfig()
        infoindex = scfg.chan_umodes.getUserInfoIndex(u)
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

        scfg = getServiceConfig()

        # Save old index, apply changes, and get new index.
        old_infoindex = scfg.chan_umodes.getUserInfoIndex(u)
        for mode, on_off in changes.iteritems():
            if on_off:
                u.chanmodes.add(mode)
            else:
                u.chanmodes.discard(mode)
        new_infoindex = scfg.chan_umodes.getUserInfoIndex(u)

        try:
            osm = self.getOnlineStateManager()
        except NotOnline:
            return

        chunks = []
        if new_infoindex == old_infoindex:
            friendly_change = "well that was pointless"
        else:
            friendly_change = "%s -> %s" % (
                scfg.chan_umodes.friendly[old_infoindex],
                scfg.chan_umodes.friendly[new_infoindex])
            osm.bsm.addNickChunk(
                chunks, irc_to_dc(u.inick), new_infoindex)

        osm.bsm.addChatChunk(
            chunks, cfg.irc_to_dc_bot,
            "%s set mode %s for %s: %s" % (
                irc_to_dc(whoset),
                self.formatChannelUserModes(changes),
                irc_to_dc(u.inick),
                friendly_change))

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
            for u in self.users.itervalues():
                if q.match(u.inick):
                    LOG.info("... and a nick to go with it: %s" % u.inick)
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
        scfg = getServiceConfig()

        for u in self.chanusers:
            nicks.append(
                (irc_to_dc(u.inick), scfg.chan_umodes.getUserInfoIndex(u)))

        for inick in cfg.virtual_nicks:
            nicks.append(
                (irc_to_dc(inick), scfg.chan_umodes.getVirtualInfoIndex()))

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
            u = self.findUser(dst_inick)
        except KeyError:
            return False

        if self.ircs:
            self.ircs.pushPrivMsg(n.inick, text, u.inick)
            return True

        return False

    def event_AddNick(self, n):
        # Might raise NickError
        inick = self.checkIncomingNick(n)

        # The inick attribute gets dropped during a KILL, so
        # event_RemoveNick won't try to send a stale QUIT.
        n.inick = inick

        # Call AddNickWithHostname after DNS succeeds (or fails)
        self.main.rdns.addRequest(n)

    def bridgeevent_AddNickWithHostname(self, n, hostname):
        # Set up hostname and hostmask.
        scfg = getServiceConfig()

        if hostname is None:
            n.hostname = Ad().setRawIPPort(n.ipp).getTextIP()
            try:
                hm = scfg.hostmasker
            except AttributeError:
                n.hostmask = n.hostname
            else:
                n.hostmask = hm.maskIPv4(n.hostname)
        else:
            n.hostname = hostname
            try:
                hm = scfg.hostmasker
            except AttributeError:
                n.hostmask = n.hostname
            else:
                n.hostmask = hm.maskHostname(n.hostname)

        osm = self.getOnlineStateManager()

        # Check channel bans on-join.
        if self.isNodeChannelBanned(n):
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

        # Announce new user to IRC.
        if self.ircs:
            self.ircs.pushNick(
                n.inick, n_user(n.ipp), n.hostname, "+iwx", n.ipp[:4],
                "Dtella %s" % n.dttag[3:])
            self.ircs.pushJoin(n.inick)

        # Send queued chat messages
        osm.cms.flushQueue(n)

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

    def formatChannelUserModes(self, changes):
        # changes: dict of {mode -> on_off}
        # Construct an IRC mode string, like "+qo-v"
        on_modes = "+"
        off_modes = "-"

        scfg = getServiceConfig()
        for m in scfg.chan_umodes.modes:
            try:
                on_off = changes[m]
            except KeyError:
                continue
            if on_off:
                on_modes += m
            else:
                off_modes += m

        return ''.join(s for s in (on_modes, off_modes) if len(s) > 1)

verifyClass(IDtellaStateObserver, IRCStateManager)


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
        scfg = getServiceConfig()
        chunks.append('I')
        joined_info = scfg.chan_umodes.getJoinedInfo()
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
        dels = ('dns_pending', 'hostname', 'hostmask', 'inick')

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
        n.dns_pending = True
        scfg = getServiceConfig()

        # If reverse DNS is not needed, sign on really soon
        if not scfg.use_rdns:
            reactor.callLater(0, self.signOn, n.ipp, None)
            return

        # Try to find an existing RDNS entry for this IP.
        ip = n.ipp[:4]
        try:
            ent = self.cache[ip]
        except KeyError:
            ent = self.cache[ip] = self.Entry()

        if ent.hostname:
            # Already have a hostname, sign on really soon
            reactor.callLater(0, self.signOn, n.ipp, ent.hostname)
        elif ent.waiting_ipps:
            # This hostname is already being queried.
            ent.waiting_ipps.add(n.ipp)
        else:
            # Start querying
            ent.waiting_ipps.add(n.ipp)
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
        # Try to find an online node corresponding to this ipp.
        osm = self.main.osm
        if not (osm and osm.syncd):
            return
        try:
            n = osm.lookup_ipp[ipp]
        except KeyError:
            return

        # Check if this node is waiting for a DNS reply.
        try:
            del n.dns_pending
        except AttributeError:
            return

        # Notify IRC State of the new node.
        ism = self.main.ism
        if ism:
            ism.bridgeevent_AddNickWithHostname(n, hostname)

