"""
Dtella - InspIRCd Service Module
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

import time
import binascii
import array
import os
from hashlib import md5, sha256

import dtella.common.core as core
import dtella.local_config as local
from dtella.common.log import LOG
from dtella.common.util import CHECK, Ad
import dtella.bridge_config as cfg
from zope.interface import implements
from zope.interface.verify import verifyClass
from dtella.bridge.bridge_server import ChannelUserModes
from dtella.bridge.bridge_server import IRCStateManager
from dtella.bridge.bridge_server import n_user
from dtella.bridge.bridge_server import irc_to_dc
from dtella.bridge.bridge_server import irc_strip
from dtella.bridge.bridge_server import getServiceConfig

B_USER = "dtbridge"
B_REALNAME = "Dtella Bridge"


class InspIRCdConfig(object):
    chan_umodes = ChannelUserModes(
        ("q", "~", "owner",    "[~] owner$ $IRC\x01$$0$"),
        ("a", "&", "super-op", "[&] super-op$ $IRC\x01$$0$"),
        ("o", "@", "op",       "[@] op$ $IRC\x01$$0$"),
        ("h", "%", "half-op",  "[%] half-op$ $IRC\x01$$0$"),
        ("v", "+", "voice",    "[+] voice$ $IRC\x01$$0$"),
        (":P", "", "loser",    "[_]$ $IRC\x01$$0$"),
        (":V", "", "virtual",  "[>] virtual$ $IRC\x01$$0$"))

    use_rdns = True

    def __init__(self, host, port, ssl, sendpass, recvpass,
                 network_name, my_host, my_name, channel,
                 hostmask_prefix, hostmask_keys):
        # Connection parameters for remote IRC server
        self.host = host                  # ip/hostname
        self.port = port                  # integer
        self.ssl = ssl                    # True/False
        self.sendpass = sendpass          # string
        self.recvpass = recvpass          # string, or None
        self.network_name = network_name  # string

        # IRC Server Link parameters. The my_host parameter must match
        # the link block in your unrealircd.conf file. 
        self.my_host = my_host
        self.my_name = my_name

        # The channel Dtella will appear in.
        self.channel = channel

        # Host masking parameters.
        # TODO: figure out InspIRCd hostmasking.
        self.hostmasker = HostMasker(hostmask_prefix, hostmask_keys)

    def startService(self, main):
        ifactory = IRCFactory(main)
        if self.ssl:
            from twisted.internet import ssl
            sslContext = ssl.ClientContextFactory()
            reactor.connectSSL(self.host, self.port, ifactory, sslContext)
        else:
            reactor.connectTCP(self.host, self.port, ifactory)


def strxor(s, v):
    return "".join(chr(ord(x) ^ v) for x in s)

def ihmac(password, challenge):
    return "HMAC-SHA256:" + sha256(
        strxor(password, 0x5C) +
        sha256(strxor(password, 0x36) + challenge).hexdigest()
        ).hexdigest()

def make_challenge():
    def remap(c):
        c = chr((ord(c) % 94) + 33)
        if c == '=':
            c = '_'
        return c
    return ''.join(remap(c) for c in os.urandom(20))


class IRCFactory(ReconnectingClientFactory):
    initialDelay = 10
    maxDelay = 60*20
    factor = 1.5

    def __init__(self, main):
        self.main = main

    def buildProtocol(self, addr):
        p = InspIRCdServer(self.main)
        p.factory = self
        return p


class InspIRCdServer(LineOnlyReceiver):
    showirc = False

    def __init__(self, main):
        self.ism = IRCStateManager(main, self)
        self.server_name = None
        self.shutdown_deferred = None

        self.ping_dcall = None
        self.ping_waiting = False
        self.capabs = {}

        # Create a nick who controls the Q-lines.  Assume it never conflicts.
        self.qline_setter = "Q_%s" % binascii.hexlify(os.urandom(8))

    def connectionMade(self):
        scfg = getServiceConfig()
        LOG.info("Connected to IRC server.")

        self.challenge = make_challenge()
        my_capabs = [
            ("NICKMAX", 32),
            ("HALFOP", 1),
            ("CHANMAX", 65),
            ("MAXMODES", 20),
            ("IDENTMAX", 12),
            ("MAXQUIT", 255),
            ("MAXTOPIC", 307),
            ("MAXKICK", 255),
            ("MAXGECOS", 128),
            ("MAXAWAY", 200),
            ("IP6SUPPORT", 1),
            ("PROTOCOL", 1105),
            ("CHALLENGE", self.challenge),
            ]
        my_capabs_str = ' '.join("%s=%s" % x for x in my_capabs)

        self.sendLine("CAPAB START")
        self.sendLine("CAPAB CAPABILITIES :%s" % my_capabs_str)
        self.sendLine("CAPAB END")

    def sendLine(self, line):
        line = line.replace('\r', '').replace('\n', '')
        print "<: %s" % line
        if self.showirc:
            LOG.log(5, "<: %s" % line)
        LineOnlyReceiver.sendLine(self, line)

    def lineReceived(self, line):
        if not line:
            return

        print ">: %s" % line
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

    def handleCmd_CAPAB(self, prefix, args):
        capab_mode = args[0]
        scfg = getServiceConfig()

        if capab_mode == "START":
            CHECK(not self.capabs)
        elif capab_mode == "CAPABILITIES":
            for capab in args[1].split():
                k, v = capab.split("=", 1)
                self.capabs[k] = v
        elif capab_mode == "END":
            challenge = self.capabs["CHALLENGE"]
            response = ihmac(scfg.sendpass, challenge)
            self.sendLine(
                "SERVER %s %s 0 :%s" %
                (scfg.my_host, response, scfg.my_name))

    def handleCmd_PING(self, prefix, args):
        LOG.info("PING? PONG!")
        scfg = getServiceConfig()
        if len(args) == 1:
            self.sendLine(":%s PONG :%s" % (scfg.my_host, args[0]))
        elif len(args) == 2:
            self.sendLine("PONG %s :%s" % (args[1], args[0]))

    def handleCmd_PONG(self, prefix, args):
        if self.ping_waiting:
            self.ping_waiting = False
            self.schedulePing()

    def handleCmd_NICK(self, prefix, args):
        # :irc1.dhirc.com NICK 1237793865 Paul <hostname> <hostname> paul + 0::ffff:1.2.3.4 :Unknown
        if len(args) == 1:
            oldnick = prefix
            newnick = args[0]
            self.ism.changeNick(oldnick, newnick)
        else:
            nick = args[1]
            self.ism.addUser(nick)

    """
    def handleCmd_SVSNICK(self, prefix, args):
        # :services.dhirc.com SVSNICK |foo Guest33400 :1236660594
        oldnick = args[0]
        newnick = args[1]

        # Is the source user a Dtella node?  Freak out.
        n = self.ism.findDtellaNode(inick=oldnick)
        if n:
            message = "Nick change to %s is impossible" % irc_to_dc(newnick)
            self.ism.kickDtellaNode(n, prefix, message)
    """

    def handleCmd_JOIN(self, prefix, args):
        # :Paul JOIN #dtella 1237797449
        nick = prefix
        chans = args[0].split(',')

        scfg = getServiceConfig()
        if scfg.channel in chans:
            self.ism.joinChannel(self.ism.findUser(nick))

    def handleCmd_FJOIN(self, prefix, args):
        # :irc1.dhirc.com FJOIN #opers 1237785045 :@%+,darkhorse ,Paul
        scfg = getServiceConfig()
        chan = args[0]
        if chan != scfg.channel:
            return

        for uinfo in args[-1].split():
            syms, nick = uinfo.split(",", 1)

            u = self.ism.findUser(nick)
            self.ism.joinChannel(u)

            changes = {}
            for sym in syms:
                try:
                    mode = scfg.chan_umodes.symbol_to_mode[sym]
                except KeyError:
                    continue
                changes[mode] = True

            if changes:
                self.ism.setChannelUserModes("", u, changes)

    def handleCmd_PART(self, prefix, args):
        nick = prefix
        chans = args[0].split(',')

        scfg = getServiceConfig()
        if scfg.channel in chans:
            CHECK(self.ism.partChannel(self.ism.findUser(nick)))

    def handleCmd_QUIT(self, prefix, args):
        nick = prefix
        try:
            u = self.ism.findUser(nick)
        except KeyError:
            LOG.error("Can't quit nick: %s" % nick)
        else:
            self.ism.removeUser(u)

    def handleCmd_KICK(self, prefix, args):
        chan = args[0]
        l33t = prefix
        n00b = args[1]
        reason = irc_strip(args[2])

        scfg = getServiceConfig()
        if chan != scfg.channel:
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
            CHECK(self.ism.partChannel(self.ism.findUser(n00b), message))

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
            self.ism.removeUser(self.ism.findUser(n00b), message)

    """
    # Treat SVSKILL the same as KILL.
    handleCmd_SVSKILL = handleCmd_KILL
    """

    def handleCmd_TOPIC(self, prefix, args):
        # :Paul TOPIC #dtella :the topic?
        chan = args[0]
        whoset = prefix
        text = irc_strip(args[-1])

        scfg = getServiceConfig()
        if chan == scfg.channel:
            self.ism.setTopic(whoset, text)

    def handleCmd_FTOPIC(self, prefix, args):
        # :irc1.dhirc.com FTOPIC #dtella 1237796893 nick!host :hello
        chan = args[0]
        whoset = args[2].split('!', 1)[0]
        text = irc_strip(args[-1])

        scfg = getServiceConfig()
        if chan == scfg.channel:
            self.ism.setTopic(whoset, text)

    def handleCmd_FMODE(self, prefix, args):
        # :Paul FMODE #dtella 1237791593 +hv-t Paul Paul
        whoset = prefix
        chan = args[0]
        change = args[2]
        nicks = args[3:]

        scfg = getServiceConfig()
        if chan != scfg.channel:
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
            elif c in scfg.chan_umodes.modes:
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
                    u = self.ism.findUser(nick)
                except KeyError:
                    LOG.error("MODE: unknown nick: %s" % nick)
                    continue

                # Schedule a mode change for this user.
                user_changes.setdefault(u, {})[c] = on_off

        # Undo mode changes for Dtella nodes.
        if unset_modes:
            self.sendLine(
                ":%s MODE %s -%s %s" % (
                    cfg.dc_to_irc_bot, scfg.channel,
                    ''.join(unset_modes), ' '.join(unset_nicks)))

        # Send IRC user mode changes to Dtella
        for u, changes in user_changes.iteritems():
            self.ism.setChannelUserModes(whoset, u, changes)

    def handleCmd_ADDLINE(self, prefix, args):
        # This is used during BURST.
        kind = args[0]

        # :irc1.dhirc.com ADDLINE Z 69.69.69.69 <Config> 1237785035 0 :hello
        if kind == 'Z':
            cidr = args[1]
            self.ism.setNetworkBan(cidr, True)

        # :irc1.dhirc.com ADDLINE Q ChanServ <Config> 1237785035 0 :Reserved
        elif kind == 'Q':
            nickmask = args[1]
            reason = args[-1]
            self.ism.addQLine(nickmask, reason)

    def handleCmd_ZLINE(self, prefix, args):
        # :Paul ZLINE 192.168.1.3/32 3600 :reason
        # :Paul ZLINE 192.168.1.3/32
        cidr = args[0]
        if len(args) == 1:
            self.ism.setNetworkBan(cidr, False)
        else:
            self.ism.setNetworkBan(cidr, True)

    def handleCmd_QLINE(self, prefix, args):
        # :Paul QLINE |name 0 :reason
        # :Paul QLINE |name
        nickmask = args[0]
        if len(args) == 1:
            self.ism.removeQLine(nickmask)
        else:
            reason = args[-1]
            self.ism.addQLine(nickmask, reason)

    def handleCmd_SERVER(self, prefix, args):
        if prefix:
            # Not from our connected server
            return

        if self.server_name:
            # Could be a dupe?  Ignore it.
            return

        # We got a reply from the our connected IRC server, so our password
        # was just accepted.  Send the Dtella state information into IRC.

        scfg = getServiceConfig()

        # Save server name
        CHECK(args[0])
        self.server_name = args[0]

        # Verify challenge response.
        if scfg.recvpass is None:
            LOG.info("Skipping validation of recvpass")
        else:
            ch_response = args[1]
            if ch_response != ihmac(scfg.recvpass, self.challenge):
                raise ValueError("Incorrect recvpass")
            LOG.info("Correct recvpass")

        LOG.info("IRC Server Name: %s" % self.server_name)

        # Tell the ReconnectingClientFactory that we're cool
        self.factory.resetDelay()

        self.sendLine("BURST %d" % time.time())
        self.pushNick(
            self.qline_setter, "qliner", scfg.my_host, "+", None,
            "I set Dtella's qline.  Don't bother me.")
        self.sendLine("ENDBURST")

    def handleCmd_ENDBURST(self, prefix, args):
        CHECK(self.server_name)
        LOG.info("Finished receiving IRC sync data.")

        self.showirc = True

        # Check for conflicting bridges.
        if self.ism.findConflictingBridge():
            LOG.error("My nick prefix is in use! Terminating.")
            self.transport.loseConnection()
            reactor.stop()
            return

        # Set up nick reservation
        scfg = getServiceConfig()

        self.sendLine(
            ":%s QLINE %s* 0 :Reserved for Dtella" %
            (self.qline_setter, cfg.dc_to_irc_prefix))
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
        scfg = getServiceConfig()

        if who == cfg.dc_to_irc_bot:
            self.pushWhoisReply(
                311, src, who, B_USER, scfg.my_host, '*', B_REALNAME)
            self.pushWhoisReply(
                312, src, who, scfg.my_host, scfg.my_name)
            self.pushWhoisReply(
                319, src, who, scfg.channel)
        else:
            n = self.ism.findDtellaNode(inick=who)
            if not (n and hasattr(n, 'hostmask')):
                return

            self.pushWhoisReply(
                311, src, who, n_user(n.ipp), n.hostmask, '*',
                "Dtella %s" % n.dttag[3:])
            self.pushWhoisReply(
                312, src, who, scfg.my_host, scfg.my_name)
            self.pushWhoisReply(
                319, src, who, scfg.channel)

            if local.use_locations:
                self.pushWhoisReply(
                    320, src, who, "Location: %s"
                    % local.hostnameToLocation(n.hostname))

        self.pushWhoisReply(
            318, src, who, "End of /WHOIS list.")

    def pushWhoisReply(self, code, target, who, *strings):
        scfg = getServiceConfig()
        line = ":%s %d %s %s " % (scfg.my_host, code, target, who)
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

        scfg = getServiceConfig()
        if target == scfg.channel:
            self.ism.sendChannelMessage(src_nick, text, flags)
	
        #Format> :Global PRIVMSG $irc3.dhirc.com :TESTING....
        #Handle global messages delivered to the bridge.
        elif target == "$" + scfg.my_host:
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

        scfg = getServiceConfig()
        if target == scfg.channel:
            self.ism.sendChannelMessage(src_nick, text, flags)
        else:
            n = self.ism.findDtellaNode(inick=target)
            if n:
                self.ism.sendPrivateMessage(n, src_nick, text, flags)

    def pushNick(self, nick, user, host, modes, ip, name):
        # If an IP was provided, convert to a base64 parameter.
        if ip:
            ip = Ad().setRawIP(ip).getTextIP()
        else:
            ip = '0.0.0.0'

        scfg = getServiceConfig()
        self.sendLine(
            ":%s NICK %d %s %s %s %s %s %s :%s" %
            (scfg.my_host, time.time(), nick, host, host, user,
             modes, ip, name))

    def pushJoin(self, nick):
        scfg = getServiceConfig()
        self.sendLine(":%s JOIN %s" % (nick, scfg.channel))

    def pushTopic(self, nick, topic):
        scfg = getServiceConfig()
        self.sendLine(
            ":%s TOPIC %s :%s" %
            (nick, scfg.channel, topic))

    def pushQuit(self, nick, reason=""):
        self.sendLine(":%s QUIT :%s" % (nick, reason))

    def pushPrivMsg(self, nick, text, target=None, action=False):
        scfg = getServiceConfig()
        if target is None:
            target = scfg.channel

        if action:
            text = "\001ACTION %s\001" % text

        self.sendLine(":%s PRIVMSG %s :%s" % (nick, target, text))

    def pushNotice(self, nick, text, target=None):
        scfg = getServiceConfig()
        if target is None:
            target = scfg.channel
        self.sendLine(":%s NOTICE %s :%s" % (nick, target, text))

    def pushBotJoin(self, do_nick=False):
        scfg = getServiceConfig()
        if do_nick:
            self.pushNick(
                # TODO: are these modes valid?
                cfg.dc_to_irc_bot, B_USER, scfg.my_host, "+B", None,
                B_REALNAME)

        # Join channel, and grant ops.
        self.pushJoin(cfg.dc_to_irc_bot)

        # Why doesn't FMODE work here?
        self.sendLine(
            ":%s MODE %s +o %s" %
            (scfg.my_host, scfg.channel, cfg.dc_to_irc_bot))

    def pushKill(self, nick):
        scfg = getServiceConfig()
        LOG.info("Killing nick: " + nick)
        self.sendLine(":%s KILL %s :%s (nick reserved for Dtella)"
                      % (scfg.my_host, nick, scfg.my_host))

    def pushRemoveQLine(self, nickmask):
        scfg = getServiceConfig()
        LOG.info("Telling network to remove Q-line: %s" % nickmask)
        self.sendLine(":%s QLINE %s" % (self.qline_setter, nickmask))

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
                scfg = getServiceConfig()
                self.sendLine(
                    ":%s PING %s" % (scfg.my_host, self.server_name))
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
        scfg = getServiceConfig()
        self.sendLine(":%s SQUIT %s :Bridge Shutting Down"
                      % (scfg.my_host, scfg.my_host))

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


class HostMasker(object):
    # UnrealIRCd-compatible hostmasking.
    # This is based on Unreal*/src/modules/cloak.c

    def __init__(self, prefix, keys):
        self.prefix = prefix
        self.keys = keys

    def maskHostname(self, host):
        KEY1, KEY2, KEY3 = self.keys
        m = self.md5
        d = self.downsample

        alpha = d(m(m("%s:%s:%s" % (KEY1, host, KEY2)) + KEY3))
        out = "%s-%X" % (self.prefix, alpha)
    
        try:
            out += host[host.index('.'):]
        except ValueError:
            pass

        return out

    def maskIPv4(self, ip):
        KEY1, KEY2, KEY3 = self.keys
        m = self.md5
        d = self.downsample
        ipstr = self.ipstr

        ip = [int(o) for o in ip.split('.')]
        alpha = d(m(m("%s:%s:%s" % (KEY2, ipstr(ip[:4]), KEY3)) + KEY1))
        beta =  d(m(m("%s:%s:%s" % (KEY3, ipstr(ip[:3]), KEY1)) + KEY2))
        gamma = d(m(m("%s:%s:%s" % (KEY1, ipstr(ip[:2]), KEY2)) + KEY3))

        return "%X.%X.%X.IP" % (alpha, beta, gamma)

    def getChecksum(self):
        KEY1, KEY2, KEY3 = self.keys
        m = self.md5

        checksum = m("%s:%s:%s" % (KEY1, KEY2, KEY3))
        return "MD5:" + ''.join(("%02x" % ord(x))[::-1] for x in checksum)

    def md5(self, in_str):
        return md5(in_str).digest()

    def downsample(self, in_str):
        a = array.array('B', in_str)
        result = 0
        for i in range(0,16,4):
            result = (result << 8) + (a[i]^a[i+1]^a[i+2]^a[i+3])
        return result

    def ipstr(self, ip):
        return '.'.join(["%d" % o for o in ip])
