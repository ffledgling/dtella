"""
Dtella - DirectConnect Interface Module
Copyright (C) 2007  Paul Marks
http://www.dtella.org/

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

from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet.protocol import ServerFactory, ClientFactory
from twisted.internet import reactor
from twisted.python.runtime import seconds
import twisted.python.log

from dtella_util import (Ad, validateNick, word_wrap, split_info,
                         split_tag, remove_dc_escapes, dcall_discard,
                         format_bytes, dcall_timeleft, get_version_string,
                         lock2key)
import dtella_core
import dtella_local
import struct
import re
import binascii

# Login Procedure
# H>C $HubName
# H<C $ValidateNick
# H>C $Hello
# H<C $GetNickList + $MyINFO
# ...



class BaseDCProtocol(LineOnlyReceiver):

    delimiter='|'


    def connectionMade(self):
        self.transport.setTcpNoDelay(True)
        self.dispatch = {}


    def sendLine(self, line):
        print "<:", line
        LineOnlyReceiver.sendLine(self, line.replace('|','&#124;'))


    def lineReceived(self, line):
        print ">:", line
        cmd = line.split(' ', 1)

        # Do a dict lookup to find the parameters for this command
        try:
            nargs, fn = self.dispatch[cmd[0]]
        except KeyError:
            # Unknown DC message
            return

        # Create the argument list
        if len(cmd) <= 1:
            args = []
        elif nargs < 0:
            nargs = -nargs
            args = cmd[1].split(' ', nargs-1)
        else:
            args = cmd[1].split(' ', nargs)

        if len(args) == nargs:
            try:
                fn(*args)
            except:
                twisted.python.log.err()


    def addDispatch(self, command, nargs, fn):
        self.dispatch[command] = (nargs, fn)


##############################################################################


class AbortTransfer_Factory(ClientFactory):

    def __init__(self, nick):
        self.nick = nick

    def buildProtocol(self, addr):
        p = AbortTransfer_Out(self.nick)
        p.factory = self
        return p


class AbortTransfer_Out(BaseDCProtocol):

    # if I initiate the connection:
    # send $MyNick + $Lock
    # (catch $Lock)
    # wait for $Key
    # -> $Key, send $Direction, $Key, $Error

    def __init__(self, nick):

        self.nick = nick
        self.key = None

        def cb():
            self.timeout_dcall = None
            self.transport.loseConnection()

        self.timeout_dcall = reactor.callLater(5.0, cb)


    def connectionMade(self):
        BaseDCProtocol.connectionMade(self)

        self.addDispatch('$Lock',  2, self.d_Lock)
        self.addDispatch('$Key',  -1, self.d_Key)

        self.sendLine("$MyNick %s" % self.nick)
        self.sendLine("$Lock FOO Pk=BAR")


    def d_Lock(self, lock, pk):
        self.key = lock2key(lock)


    def d_Key(self, key):
        self.sendLine("$Direction Upload 12345")
        self.sendLine("$Key %s" % self.key)
        self.sendLine("$Error Cancelled by Dtella")
        self.transport.loseConnection()


    def connectionLost(self, reason):
        dcall_discard(self, 'timeout_dcall')



class AbortTransfer_In(BaseDCProtocol):

    # if I receive the connection:
    # receive $MyNick
    # wait for $Lock
    # -> send $MyNick + $Lock + $Direction + $Key
    # wait for $Key
    # -> send $Error

    def __init__(self, nick, dch):

        self.nick = nick
        
        # Steal connection from the DCHandler
        self.factory = dch.factory
        self.makeConnection(dch.transport)
        self.transport.protocol = self

        # Steal the rest of the data
        self._buffer = dch._buffer
        dch.lineReceived = self.lineReceived

        def cb():
            self.timeout_dcall = None
            self.transport.loseConnection()

        self.timeout_dcall = reactor.callLater(5.0, cb)


    def connectionMade(self):
        BaseDCProtocol.connectionMade(self)

        self.addDispatch('$Lock', 2, self.d_Lock)


    def d_Lock(self, lock, pk):
        self.sendLine("$MyNick %s" % self.nick)
        self.sendLine("$Lock FOO Pk=BAR")
        self.sendLine("$Direction Upload 12345")
        self.sendLine("$Key %s" % lock2key(lock))

        self.addDispatch('$Key', -1, self.d_Key)


    def d_Key(self, key):
        self.sendLine("$Error Cancelled by Dtella")
        self.transport.loseConnection()


    def connectionLost(self, reason):
        dcall_discard(self, 'timeout_dcall')


##############################################################################


class DCHandler(BaseDCProtocol):


    def __init__(self, main):
        self.main = main


    def connectionMade(self):
        BaseDCProtocol.connectionMade(self)

        self.info = ''
        self.nick = ''
        self.bot = DtellaBot(self, '*Dtella')

        # Handlers which can be used before attaching to Dtella
        self.addDispatch('$ValidateNick',   1, self.d_ValidateNick)
        self.addDispatch('$GetNickList',    0, self.d_GetNickList)
        self.addDispatch('$MyINFO',        -3, self.d_MyInfo)
        self.addDispatch('$GetINFO',        2, self.d_GetInfo)
        self.addDispatch('',                0, self.d_KeepAlive)
        self.addDispatch('$KillDtella',     0, self.d_KillDtella)

        self.addDispatch('$MyNick',         1, self.d_MyNick)
        
        # Chat messages waiting to be sent
        self.chatq = []
        self.chat_counter = 99999
        self.chatRate_dcall = None

        # ['login_N', 'login_G', 'login_I', 'queued', 'ready', 'invisible']
        self.state = 'login_N'

        self.queued_dcall = None
        self.autoRejoin_dcall = None

        self.sendLine("$Lock FOO Pk=BAR")
        #self.pushTopic()

        self.scheduleChatRateControl()


    def isOnline(self):
        osm = self.main.osm
        return (self.state == 'ready' and osm and osm.syncd)


    def connectionLost(self, reason):

        self.main.removeDCHandler(self)

        dcall_discard(self, 'chatRate_dcall')
        dcall_discard(self, 'autoRejoin_dcall')


    def fatalError(self, text):
        self.pushStatus("ERROR: %s" % text)
        self.transport.loseConnection()


    def d_KillDtella(self):
        reactor.stop()


    def d_MyNick(self, nick):
        # This indicates a file transfer connection.
        if self.state != 'login_N':
            self.fatalError("$MyNick not expected.")
            return

        if not self.main.abort_nick:
            self.loseConnection()
            return

        # Transfer my state to the connection abort handler
        AbortTransfer_In(self.main.abort_nick, self)
        self.main.abort_nick = None


    def d_ValidateNick(self, nick):

        if self.state != 'login_N':
            self.fatalError("$ValidateNick not expected.")
            return

        # Next, we expect $GetNickList
        self.state = 'login_G'

        reason = validateNick(nick)

        if reason:
            self.pushStatus("Your nick is invalid: %s" % reason)
            self.pushStatus("Please fix it and reconnect.  Goodbye.")
            self.transport.loseConnection()
            return

        self.nick = nick

        self.pushHello(self.nick)


    def d_GetInfo(self, nick, _):

        if nick == self.bot.nick:
            dcinfo = "Local Dtella Bot$ $Bot\x01$$0$"
            self.pushInfo(nick, dcinfo)
            return

        if not self.isOnline():
            return

        try:
            n = self.main.osm.nkm.lookupNick(nick)
        except KeyError:
            return

        if n.dcinfo:
            self.pushInfo(n.nick, n.dcinfo)
        

    def d_GetNickList(self):

        if self.state == 'login_N':
            self.fatalError("Got $GetNickList, expected $ValidateNick")
            return

        # Next, we expect $MyINFO
        if self.state == 'login_G':
            self.state = 'login_I'

        # Me and the bot are ALWAYS online
        nicks = [self.bot.nick, self.nick]

        # Add in the Dtella nicks, if we're fully online (DC and Dtella)
        if self.isOnline():
            nicks = set(nicks)
            nicks.update(self.main.osm.nkm.getNickList())
            nicks = list(nicks)

        nicks.sort()

        self.sendLine("$NickList %s$$" % '$$'.join(nicks))
        self.sendLine("$OpList %s$$" % self.bot.nick)


    def d_MyInfo(self, _1, _2, info):

        if self.state == 'login_N':
            self.fatalError("Got $MyINFO, expected $ValidateNick")
            return

        elif self.state == 'login_G':
            self.fatalError("Got $MyINFO, expected $GetNickList")
            return

        # Save my new info
        self.info = info.replace('\r','').replace('\n','')

        if self.state == 'login_I':
            self.loginComplete()

        elif self.isOnline():
            self.main.osm.updateMyInfo()


    def loginComplete(self):

        assert self.state == 'login_I'

        if self.main.dch is None:
            self.attachMeToDtella()

        elif self.main.pending_dch is None:
            self.state = 'queued'
            self.main.pending_dch = self

            def cb():
                self.queued_dcall = None
                self.main.pending_dch = None
                self.pushStatus("Nope, it didn't leave.  Goodbye.")
                self.transport.loseConnection()

            self.pushStatus(
                "Another DC client is already using Dtella on this computer.")
            self.pushStatus(
                "Waiting 5 seconds for it to leave.")

            self.queued_dcall = reactor.callLater(5.0, cb)

        else:
            self.pushStatus(
                "Dtella is busy with other DC connections from your "
                "computer.  Goodbye.")
            self.transport.loseConnection()


    def attachMeToDtella(self):

        assert (self.main.dch is None)

        if self.state == 'queued':
            self.queued_dcall.cancel()
            self.queued_dcall = None
            self.pushStatus(
                "The other client left.  Resuming normal connection.")

        dcall_discard(self, 'queued_dcall')

        # Add the post-login handlers
        self.addDispatch('$ConnectToMe',      2, self.d_ConnectToMe)
        self.addDispatch('$RevConnectToMe',   2, self.d_RevConnectToMe)
        self.addDispatch('$Search',          -2, self.d_Search)
        self.addDispatch('$To:',             -5, self.d_PrivateMsg)
        self.addDispatch("<%s>" % self.nick, -1, self.d_PublicMsg)

        self.state = 'ready'
        self.main.addDCHandler(self)

        # If Dtella's online too, then sync both ways
        if self.isOnline():
            self.main.osm.updateMyInfo()
            self.d_GetNickList()
            self.grabDtellaTopic()


    def formatMyInfo(self):
        # Build and return a hacked-up version of my info string.

        # Get version string
        ver_string = get_version_string()

        # Split info string
        try:
            info = split_info(self.info)
        except ValueError:
            # No info.  Just use the offline version tag
            return "<%s>" % ver_string

        # Split description into description and <tag>
        desc, tag = split_tag(info[0])

        # Update tag
        if tag:
            info[0] = "%s<%s,%s>" % (desc, tag, ver_string)
        else:
            info[0] = "%s<%s>" % (desc, ver_string)

        if dtella_local.use_locations:
            # Try to get my location name.
            try:
                ad = Ad().setRawIPPort(self.main.osm.me.ipp)
                loc = self.main.location[ad.getTextIP()]
            except (AttributeError, KeyError):
                loc = None

            # If I got a location name, splice it into my connection field
            if loc:
                # Append location suffix, if it exists
                suffix = self.main.state.suffix
                if suffix:
                    loc = '%s|%s' % (loc, suffix)
                
                info[2] = loc + info[2][-1:]

        info = '$'.join(info)

        if len(info) > 255:
            self.pushStatus("*** Your info string is too long!")
            info = ''

        return info


    def d_Search(self, addr_string, search_string):
        # Send a search request

        if not self.isOnline():
            self.pushStatus("Can't Search: Not online!")
            return

        if len(search_string) > 255:
            self.pushStatus("Search string too long")
            return

        osm = self.main.osm

        packet = osm.mrm.broadcastHeader('SQ', osm.me.ipp)
        packet.append(struct.pack('!I', osm.mrm.getPacketNumber_search()))

        packet.append(struct.pack('!B', len(search_string)))
        packet.append(search_string)
        
        osm.mrm.newMessage(''.join(packet), tries=4)

        # If local searching is enabled, send the search to myself
        if self.main.state.localsearch:
            self.pushSearchRequest(osm.me.ipp, search_string)


    def d_PrivateMsg(self, nick, _1, _2, _3, text):

        text = remove_dc_escapes(text)
        
        if nick == self.bot.nick:

            # No ! is needed for commands in the private message context
            if text[:1] == '!':
                text = text[1:]

            def out(text):
                if text is not None:
                    self.bot.say(text)
            
            self.bot.commandInput(out, text)
            return

        if len(text) > 10:
            shorttext = text[:10] + '...'
        else:
            shorttext = text

        def fail_cb(detail):
            self.pushPrivMsg(
                nick,
                "*** Your message \"%s\" could not be sent: %s"
                % (shorttext, detail))

        if not self.isOnline():
            fail_cb("You're not online.")
            return

        try:
            n = self.main.osm.nkm.lookupNick(nick)
        except KeyError:
            fail_cb("User doesn't seem to exist.")
            return

        n.event_PrivateMessage(self.main, text, fail_cb)


    def d_ConnectToMe(self, nick, addr):

        osm = self.main.osm

        def fail_cb(detail):
            self.pushStatus(
                "*** Connection to '%s' failed: %s" % (nick, detail))

            # TODO: doesn't catch everything
            ad = Ad().setTextIPPort(addr)
            reactor.connectTCP(
                '127.0.0.1', ad.port, AbortTransfer_Factory(nick))


        if not self.isOnline():
            fail_cb("you're not online.")
            return

        try:
            dc_ad = Ad().setTextIPPort(addr)
        except ValueError:
            fail_cb("malformed address.")
            return

        try:
            n = osm.nkm.lookupNick(nick)
        except KeyError:
            if nick == self.bot.nick:
                fail_cb("can't connect to yourself!")
            else:
                fail_cb("user doesn't seem to exist.")
            return

        if n.checkRevConnectWindow():
            # If we're responding to a RevConnect, disable errors
            def fail_cb(detail):
                pass

        elif self.isLeech():
            # I'm a leech
            return

        n.event_ConnectToMe(self.main, dc_ad.port, fail_cb)


    def d_RevConnectToMe(self, _, nick):

        osm = self.main.osm

        def fail_cb(detail):
            self.pushStatus(
                "*** Connection to '%s' failed: %s" % (nick, detail))

            # TODO: doesn't catch everything
            self.main.abort_nick = nick
            self.sendLine(
                "$ConnectToMe %s 127.0.0.1:%d"
                % (self.nick, self.factory.listen_port))

        if not self.isOnline():
            fail_cb("you're not online.")
            return

        try:
            n = osm.nkm.lookupNick(nick)
        except KeyError:
            if nick == self.bot.nick:
                fail_cb("can't connect to yourself!")
            else:
                fail_cb("user doesn't seem to exist.")
            return

        if self.isLeech():
            # I'm a leech
            return

        n.event_RevConnectToMe(self.main, fail_cb)


    def isLeech(self):
        # If I don't meet the minimum share, yell and return True

        osm = self.main.osm
        minshare = self.main.dnsh.minshare

        if osm.me.shared < minshare:
            self.pushStatus(
                "*** You must share at least %s in order to download!  "
                "(You currently have %s)" %
                (format_bytes(minshare), format_bytes(osm.me.shared)))
            return True

        return False


    def d_PublicMsg(self, text):

        text = remove_dc_escapes(text)

        # Route commands to the bot
        if text[:1] == '!':

            def out(out_text, flag=[True]):

                # If the bot produces output, inject our text input before
                # the first line.
                if flag[0]:
                    self.pushChatMessage(self.nick, text)
                    flag[0] = False

                if out_text is not None:
                    self.pushStatus(out_text)
            
            if self.bot.commandInput(out, text[1:], '!'):
                return

        if not self.isOnline():
            self.pushStatus("*** You must be online to chat!")
            return

        text = text.replace('\r\n','\n').replace('\r','\n')

        for line in text.split('\n'):

            # Skip empty lines
            if not line:
                continue

            # Limit length
            if len(line) > 1024:
                line = line[:1024-12] + ' [Truncated]'

            flags = 0

            # Check for /me
            if len(line) > 4 and line[:4].lower() in ('/me ','+me ','!me '):
                line = line[4:]
                flags |= dtella_core.SLASHME_BIT

            # Check rate limiting
            if self.chat_counter > 0:

                # Send now
                self.chat_counter -= 1
                self.broadcastChatMessage(flags, line)

            else:
                # Put in a queue
                if len(self.chatq) < 5:
                    self.chatq.append( (flags, line) )
                else:
                    self.pushStatus(
                        "*** Chat throttled.  Stop typing so much!")
                    break


    def d_KeepAlive(self):
        # Doesn't do much really
        self.sendLine('')


    def pushChatMessage(self, nick, text):
        self.sendLine("<%s> %s" % (nick, text))


    def pushInfo(self, nick, dcinfo):
        self.sendLine('$MyINFO $ALL %s %s' % (nick, dcinfo))


    def pushTopic(self, topic=None):
        if topic:
            self.sendLine("$HubName %s - %s" % (dtella_local.hub_name, topic))
        else:
            self.sendLine("$HubName %s" % dtella_local.hub_name)


    def pushHello(self, nick):
        self.sendLine('$Hello %s' % nick)


    def pushQuit(self, nick):
        self.sendLine('$Quit %s' % nick)


    def pushConnectToMe(self, ad):
        self.sendLine("$ConnectToMe %s %s" % (self.nick, ad.getTextIPPort()))


    def pushRevConnectToMe(self, nick):
        self.sendLine("$RevConnectToMe %s %s" % (nick, self.nick))        


    def pushSearchRequest(self, ipp, search_string):
        ad = Ad().setRawIPPort(ipp)
        self.sendLine("$Search %s %s" % (ad.getTextIPPort(), search_string))


    def pushPrivMsg(self, nick, text):
        self.sendLine("$To: %s From: %s $<%s> %s"
                      % (self.nick, nick, nick, text))


    def pushStatus(self, text):
        self.pushChatMessage(self.bot.nick, text)


    def scheduleChatRateControl(self):
        if self.chatRate_dcall:
            return

        def cb():
            self.chatRate_dcall = reactor.callLater(1.0, cb)
           
            if self.chatq:
                args = self.chatq.pop(0)
                self.broadcastChatMessage(*args)
            else:
                self.chat_counter = min(5, self.chat_counter + 1)

        cb()


    def broadcastChatMessage(self, flags, text):

        assert self.isOnline()

        osm = self.main.osm

        packet = osm.mrm.broadcastHeader('CH', osm.me.ipp)
        packet.append(struct.pack('!I', osm.mrm.getPacketNumber_chat()))

        packet.append(osm.me.nickHash())
        packet.append(struct.pack('!BH', flags, len(text)))
        packet.append(text)

        osm.mrm.newMessage(''.join(packet), tries=4)

        # Echo back to the DC client
        if flags & dtella_core.SLASHME_BIT:
            nick = "*"
            text = "%s %s" % (osm.me.nick, text)
        else:
            nick = osm.me.nick

        self.pushChatMessage(nick, text)


    def goInvisible(self, rejoin_time=None):
        # Node will become visible again if:
        # 1. Dtella node loses its connection
        # 2. User types !REJOIN
        # 3. DC client reconnects (creates a new DCHandler)

        assert self.state == 'ready'

        if self.main.osm:
            self.main.osm.nkm.quitEverybody()

        self.pushTopic()

        self.state = 'invisible'
        del self.chatq[:]

        if rejoin_time is None:
            return

        # Automatically rejoin the chat after a timeout period
        dcall_discard(self, 'autoRejoin_dcall')

        def cb():
            self.autoRejoin_dcall = None
            self.pushStatus("Automatically rejoining...")
            self.doRejoin()

        self.autoRejoin_dcall = reactor.callLater(rejoin_time, cb)


    # Precompile a regex for pushSearchResult
    searchreply_re = re.compile(r"^\$SR ([^ |]+) ([^|]*) \([^ |]+\)\|?$")

    def pushSearchResult(self, data):

        m = self.searchreply_re.match(data)
        if not m:
            # Doesn't look like a search reply
            return

        nick = m.group(1)
        data = m.group(2)

        # If I get results from myself, map them to the bot's nick
        if nick == self.nick:
            nick = self.bot.nick

        self.sendLine("$SR %s %s (127.0.0.1:%d)"
                      % (nick, data, self.factory.listen_port))


    def grabDtellaTopic(self):
        if self.isOnline():
            tm = self.main.osm.tm
            self.pushTopic(tm.topic)
            if tm.topic:
                self.pushStatus(tm.getFormattedTopic())


    def nickCollision(self):

        self.goInvisible()

        self.pushStatus(
            "The nick '%s' is already in use on this network." % self.nick)
        self.pushStatus(
            "Please change your nick, or type !REJOIN to try again.")


    def remoteNickCollision(self):

        text = (
            "*** Another node on the network has reported that your nick "
            "seems to be in a conflicting state.  This could prevent your "
            "chat and search messages from reaching everyone, so it'd be "
            "a good idea to try changing your nick.  Or you could wait "
            "and see if the problem resolves itself."
            )

        for line in word_wrap(text):
            self.pushStatus(line)


    def kickMe(self, l33t, reason, rejoin):

        if rejoin:
            # Pop back on after 5 minutes
            self.goInvisible(rejoin_time=60*5)
        else:
            self.goInvisible()

        # Show kick text
        self.pushStatus("You were kicked by %s: %s" % (l33t, reason))
        self.pushStatus("Type !REJOIN to get back in.")



    def doRejoin(self):
        if self.state != 'invisible':
            return

        dcall_discard(self, 'autoRejoin_dcall')

        self.state = 'ready'

        if self.main.osm:
            # Maybe tell the network that I'm back (unless it collides)
            self.main.osm.updateMyInfo()
            
            # Maybe send a full nicklist+topic (if the update succeeded)
            self.d_GetNickList()
            self.grabDtellaTopic()


    def dtellaShutdown(self):
        # When the dtella node leaves the network, and we're still
        # in an invisible state, reset to normal for the next login.

        if self.state == 'invisible':
            self.state = 'ready'

        dcall_discard(self, 'autoRejoin_dcall')

        # Wipe out the topic
        self.pushTopic()

        # Wipe out my outgoing chat queue
        del self.chatq[:]


    def isProtectedNick(self, nick):
        return (nick.lower() in (self.nick.lower(), self.bot.nick.lower()))


    def event_AddNick(self, n):
        if not self.isProtectedNick(n.nick):
            self.pushHello(n.nick)
    

    def event_RemoveNick(self, n, reason):
        if not self.isProtectedNick(n.nick):
            self.pushQuit(n.nick)


    def event_UpdateInfo(self, n):
        if n.dcinfo:
            self.pushInfo(n.nick, n.dcinfo)


    def event_ChatMessage(self, n, nick, text, flags):
        if flags & dtella_core.NOTICE_BIT:
            self.pushChatMessage(("*N# %s" % nick), text)
        elif flags & dtella_core.SLASHME_BIT:
            self.pushChatMessage("*", "%s %s" % (nick, text))
        else:
            self.pushChatMessage(nick, text)


##############################################################################


class DCFactory(ServerFactory):
    
    def __init__(self, main, listen_port):
        self.main = main
        self.listen_port = listen_port # spliced into search results
        
    def buildProtocol(self, addr):
        if addr.host != '127.0.0.1':
            return None

        p = DCHandler(self.main)

        p.factory = self
        return p


##############################################################################


class DtellaBot(object):
    # This holds the logic behind the "*Dtella" user

    def __init__(self, dch, nick):
        self.dch = dch
        self.main = dch.main
        self.nick = nick

        self.dbg_show_packets = False


    def say(self, txt):
        self.dch.pushPrivMsg(self.nick, txt)


    def commandInput(self, out, line, prefix=''):

        # Sanitize
        line = line.replace('\r', ' ').replace('\n', ' ')

        cmd = line.upper().split()

        if not cmd:
            return False

        try:
            f = getattr(self, 'handleCmd_' + cmd[0])
        except AttributeError:
            if prefix:
                return False
            else:
                out("Unknown command '%s'.  Type %sHELP for help." %
                    (cmd[0], prefix))
                return True

        # Filter out location-specific commands
        if not dtella_local.use_locations:
            if cmd[0] in self.location_cmds:
                return False
            
        if cmd[0] in self.freeform_cmds:
            try:
                text = line.split(' ', 1)[1]
            except IndexError:
                text = None

            f(out, text, prefix)
            
        else:
            def wrapped_out(line):
                for l in word_wrap(line):
                    if l:
                        out(l)
                    else:
                        out(" ")
           
            f(wrapped_out, cmd[1:], prefix)

        return True


    def syntaxHelp(self, out, key, prefix):

        try:
            head = self.bighelp[key][0]
        except KeyError:
            return

        out("Syntax: %s%s %s" % (prefix, key, head))
        out("Type '%sHELP %s' for more information." % (prefix, key))


    freeform_cmds = frozenset(['TOPIC','SUFFIX','DEBUG'])

    location_cmds = frozenset(['SUFFIX','USERS','SHARED','DENSE'])

    
    minihelp = [
        ("--",         "ACTIONS"),
        ("REJOIN",     "Hop back online after a kick or collision"),
        ("ADDPEER",    "Add the address of another node to your cache"),
        ("REBOOT",     "Exit from the network and immediately reconnect"),
        ("TERMINATE",  "Completely kill your current Dtella process."),
        ("--",         "SETTINGS"),
        ("TOPIC",      "View or change the global topic"),
        ("SUFFIX",     "View or change your location suffix"),
        ("UDP",        "Change Dtella's peer communication port"),
        ("LOCALSEARCH","View or toggle local search results."),
        ("PERSISTENT", "View or toggle persistent mode"),
        ("--",         "INFORMATION"),
        ("VERSION",    "View information about your Dtella version."),
        ("USERS",      "Show how many users exist at each location"),
        ("SHARED",     "Show how many bytes are shared at each location"),
        ("DENSE",      "Show the bytes/user density for each location"),
        ("RANK",       "Compare your share size with everyone else"),
        ]


    bighelp = {
        "REJOIN":(
            "",
            "If you are kicked from the chat system, or if you attempt to use "
            "a nick which is already occupied by someone else, your node "
            "will remain connected to the peer network in an invisible state. "
            "If this happens, you can use the REJOIN command to hop back "
            "online.  Note that this is only useful after a nick collision "
            "if the conflicting nick has left the network."
            ),

        "TOPIC":(
            "<text>",
            "If no argument is provided, this command will display the "
            "current topic for the network.  This is the same text which "
            "is shown in the title bar.  If you provide a string of text, "
            "this will attempt to set a new topic.  Note that if Dtella "
            "is bridged to an IRC network, the admins may decide to lock "
            "the topic to prevent changes."
            ),

        "SUFFIX":(
            "<suffix>",
            "This command appends a suffix to your location name, which "
            "is visible in the Speed/Connection column of everyone's DC "
            "client.  Typically, this is where you put your room number. "
            "If you provide no arguments, this will display the "
            "current suffix.  To clear the suffix, just follow the command "
            "with a single space."
            ),

        "TERMINATE":(
            "",
            "This will completely kill your current Dtella node.  If you "
            "want to rejoin the network afterward, you'll have to go "
            "start up the Dtella program again."
            ),

        "VERSION":(
            "",
            "This will display your current Dtella version number.  If "
            "available, it will also display the minimum required version, "
            "the newest available version, and a download link."
            ),

        "LOCALSEARCH":(
            "<ON | OFF>",
            "If local searching is enabled, then when you search, you will "
            "see search results from the *Dtella user, which are actually "
            "hosted on your computer.  Use this command without any arguments "
            "to see whether local searching is currently enabled or not."
            ),

        "USERS":(
            "",
            "This will list all the known locations, and show how many "
            "people are currently connecting from each."
            ),

        "SHARED":(
            "",
            "This will list all the known locations, and show how many "
            "bytes of data are being shared from each."
            ),
        
        "DENSE":(
            "",
            "This will list all the known locations, and show the calculated "
            "share density (bytes-per-user) for each."
            ),
        
        "RANK":(
            "<nick>",
            "Compare your share size with everyone else in the network, and "
            "show which place you're currently in.  If <nick> is provided, "
            "this will instead display the ranking of the user with that nick."
            ),
        
        "UDP":(
            "<port>",
            "Specify a port number between 1-65536 to change the UDP port "
            "that Dtella uses for peer-to-peer communication.  If you don't "
            "provide a port number, this will display the port number which "
            "is currently in use."
            ),

        "ADDPEER":(
            "<ip>:<port>",
            "If Dtella is unable to locate any neighbor nodes using the "
            "remote config data or your local neighbor cache, then you "
            "can use this command to manually add the address of an existing "
            "node that you know about."
            ),

        "REBOOT":(
            "",
            "This command takes no arguments.  It will cause your node to "
            "exit from the network, and immediately restart the connection "
            "process.  Use of this command shouldn't be necessary for "
            "normal operation."
            ),

        "PERSISTENT":(
            "<ON | OFF>",
            "This option controls how Dtella will behave when it is not "
            "attached to a Direct Connect client.  When PERSISTENT mode is "
            "OFF, Dtella will automatically close its peer connection after "
            "5 minutes of inactivity.  When this mode is ON, Dtella will "
            "try to stay connected to the network continuously.  To see "
            "whether PERSISTENT is enabled, enter the command with no "
            "arguments."
            )
        }


    def handleCmd_HELP(self, out, args, prefix):

        if len(args) == 0:
            out("This is your local Dtella bot.  You can send messages here "
                "to control the various features of Dtella.  A list of "
                "commands is provided below.  Note that you can PM a command "
                "directly to the %s user, or enter it in the main chat "
                "window prefixed with an exclamation point (!)" % self.nick)

            for command, description in self.minihelp:

                # Filter location-specific commands
                if not dtella_local.use_locations:
                    if command in self.location_cmds:
                        continue
                
                if command == "--":
                    out("")
                    out("  --%s--" % description)
                else:
                    out("  %s%s - %s" % (prefix, command, description))

            out("")
            out("For more detailed information, type: "
                "%sHELP <command>" % prefix)

        else:
            key = ' '.join(args)

            # If they use a !, strip it off
            if key[:1] == '!':
                key = key[1:]

            try:
                # Filter location-specific commands
                if not dtella_local.use_locations:
                    if key in self.location_cmds:
                        raise KeyError
                    
                (head, body) = self.bighelp[key]
                
            except KeyError:
                out("Sorry, no help available for '%s'." % key)

            else:
                out("Syntax: %s%s %s" % (prefix, key, head))
                out("")
                out(body)


    def handleCmd_REBOOT(self, out, args, prefix):

        if len(args) == 0:
            out("Rebooting Node...")
            self.main.shutdown(reconnect='no')
            self.main.newConnectionRequest()
            return

        self.syntaxHelp(out, 'REBOOT', prefix)


    def handleCmd_UDP(self, out, args, prefix):
        if len(args) == 0:
            out("Dtella's UDP port is currently set to: %d"
                % self.main.state.udp_port)
            return

        elif len(args) == 1:
            try:
                port = int(args[0])
                if not 1 <= port <= 65535:
                    raise ValueError
            except ValueError:
                pass
            else:
                if self.main.changeUDPPort(port):
                    out("Changing UDP port to: %d." % port)
                else:
                    out("Can't change UDP port; busy.")
                return
            
        self.syntaxHelp(out, 'UDP', prefix)


    def handleCmd_ADDPEER(self, out, args, prefix):

        if len(args) == 1:
            try:
                ad = Ad().setTextIPPort(args[0])
                if ad.auth_s():
                    self.main.state.refreshPeer(ad, 0)
                    out("Added to peer cache: %s" % ad.getTextIPPort())

                    # Jump-start stuff if it's not already going
                    self.main.newConnectionRequest()
                else:
                    out("The address '%s' is not permitted on this network."
                        % ad.getTextIPPort())
                return

            except ValueError:
                pass

        self.syntaxHelp(out, 'ADDPEER', prefix)


    def handleCmd_PERSISTENT(self, out, args, prefix):
        if len(args) == 0:
            if self.main.state.persistent:
                out("Persistent mode is currently ON.")
            else:
                out("Persistent mode is currently OFF.")
            return

        if len(args) == 1:
            if args[0] == 'ON':
                out("Set persistent mode to ON.")
                self.main.state.persistent = True
                self.main.state.saveState()

                if self.main.osm:
                    self.main.osm.updateMyInfo()

                self.main.newConnectionRequest()
                return

            elif args[0] == 'OFF':
                out("Set persistent mode to OFF.")
                self.main.state.persistent = False
                self.main.state.saveState()

                if self.main.osm:
                    self.main.osm.updateMyInfo()
                return

        self.syntaxHelp(out, 'PERSISTENT', prefix)


    def handleCmd_LOCALSEARCH(self, out, args, prefix):
        if len(args) == 0:
            if self.main.state.localsearch:
                out("Local searching is currently ON.")
            else:
                out("Local searching is currently OFF.")
            return

        if len(args) == 1:
            if args[0] == 'ON':
                out("Set local searching to ON.")
                self.main.state.localsearch = True
                self.main.state.saveState()
                return

            elif args[0] == 'OFF':
                out("Set local searching to OFF.")
                self.main.state.localsearch = False
                self.main.state.saveState()
                return

        self.syntaxHelp(out, 'LOCALSEARCH', prefix)


    def handleCmd_REJOIN(self, out, args, prefix):

        if len(args) == 0:

            if self.dch.state != 'invisible':
                out("Can't rejoin: You're not invisible!")
                return

            out("Rejoining...")
            self.dch.doRejoin()
            return
        
        self.syntaxHelp(out, 'REJOIN', prefix)


    def handleCmd_USERS(self, out, args, preifx):

        if not self.dch.isOnline():
            out("You must be online to use %sUSERS." % prefix)
            return
        
        self.showStats(
            out,
            "User Counts",
            lambda u,b: u,
            lambda v: "%d" % v,
            peers_only=False
            )


    def handleCmd_SHARED(self, out, args, preifx):

        if not self.dch.isOnline():
            out("You must be online to use %sSHARED." % prefix)
            return
        
        self.showStats(
            out,
            "Bytes Shared",
            lambda u,b: b,
            lambda v: "%s" % format_bytes(v),
            peers_only=True
            )


    def handleCmd_DENSE(self, out, args, prefix):

        if not self.dch.isOnline():
            out("You must be online to use %sDENSE." % prefix)
            return

        def compute(u,b):
            try:
                return (b/u, u)
            except ZeroDivisionError:
                return (0, u)
        
        self.showStats(
            out,
            "Share Density",
            compute,
            lambda v: "%s/user (%d)" % (format_bytes(v[0]), v[1]),
            peers_only=True
            )


    def handleCmd_RANK(self, out, args, prefix):

        if not self.dch.isOnline():
            out("You must be online to use %sRANK." % prefix)
            return

        osm = self.main.osm

        tie = False
        rank = 1

        target = None

        if len(args) == 0:
            target = osm.me
        elif len(args) == 1:
            try:
                target = osm.nkm.lookupNick(args[0])
            except KeyError:
                out("The nick '%s' cannot be located." % args[0])
                return
        else:
            self.syntaxHelp(out, 'RANK', prefix)
            return
        
        if target is osm.me:
            who = "You are"
        else:
            who = "%s is" % target.nick

        for n in osm.nkm.nickmap.values():
            if n is target:
                continue

            if n.shared > target.shared:
                rank += 1
            elif n.shared == target.shared:
                tie = True

        try:
            suffix = {1:'st',2:'nd',3:'rd'}[rank % 10]
            if 11 <= (rank % 100) <= 13:
                raise KeyError
        except KeyError:
            suffix = 'th'

        if tie:
            tie = "tied for"
        else:
            tie = "in"

        out("%s %s %d%s place, with a share size of %s." %
            (who, tie, rank, suffix, format_bytes(target.shared))
            )
        
    def handleCmd_TOPIC(self, out, topic, prefix):
        
        if not self.dch.isOnline():
            out("You must be online to use %sTOPIC." % prefix)
            return

        tm = self.main.osm.tm

        if topic is None:
            out(tm.getFormattedTopic())
        else:
            out(None)
            tm.broadcastNewTopic(topic)


    def handleCmd_SUFFIX(self, out, text, prefix):

        if text is None:
            out("Your location suffix is \"%s\"" % self.main.state.suffix)
            return

        text = text[:8].rstrip().replace('$','')

        self.main.state.suffix = text
        self.main.state.saveState()
        
        out("Set location suffix to \"%s\"" % text)

        osm = self.main.osm
        if osm:
            osm.updateMyInfo()


    def showStats(self, out, title, compute, format, peers_only):

        assert self.dch.isOnline()

        # Count users and bytes
        ucount = {}
        bcount = {}

        # Collect user count and share size
        for n in self.main.osm.nkm.nickmap.values():

            if peers_only and not n.is_peer:
                continue
            
            try:
                ucount[n.location] += 1
                bcount[n.location] += n.shared
            except KeyError:
                ucount[n.location] = 1
                bcount[n.location] = n.shared

        # Collect final values
        values = {}
        for loc in ucount:
            values[loc] = compute(ucount[loc], bcount[loc])

        # Sort by value, in descending order
        locs = values.keys()
        locs.sort(key=lambda loc: values[loc], reverse=True)

        overall = compute(sum(ucount.values()), sum(bcount.values()))

        # Build info string and send it
        out("/== %s, by Location ==\\" % title)
        for loc in locs:
            out("| %s <= %s" % (format(values[loc]), loc))
        out("|")
        out("\\_ Overall: %s _/" % format(overall))


    def handleCmd_VERSION(self, out, args, prefix):
        if len(args) == 0:
            out("You have Dtella version %s." % dtella_local.version)

            if self.main.dnsh.version:
                min_v, new_v, url = self.main.dnsh.version
                out("The minimum required version is %s." % min_v)
                out("The latest posted version is %s." % new_v)
                out("Download Link: %s" % url)

            return

        self.syntaxHelp(out, 'VERSION', prefix)


    def handleCmd_TERMINATE(self, out, args, prefix):
        if len(args) == 0:
            reactor.stop()
            return

        self.syntaxHelp(out, 'TERMINATE', prefix)


    def handleCmd_VERSION_OVERRIDE(self, out, text, prefix):
        if 'old_version' in self.main.blockers:
            out("Overriding minimum version!  Don't be surprised "
                "if something breaks.")
            self.main.removeBlocker('old_version')
        else:
            out("%sVERSION_OVERRIDE not needed." % prefix)


    def handleCmd_DEBUG(self, out, text, prefix):

        out(None)
        
        if not text:
            return

        text = text.strip().lower()
        args = text.split()

        if args[0] == "nbs":
            self.debug_neighbors(out)

        elif args[0] == "nodes":
            try:
                sortkey = int(args[1])
            except (IndexError, ValueError):
                sortkey = 0
            self.debug_nodes(out, sortkey)

        elif args[0] == "packets":
            if len(args) < 2:
                pass
            elif args[1] == "on":
                self.dbg_show_packets = True
            elif args[1] == "off":
                self.dbg_show_packets = False


    def debug_neighbors(self, out):

        osm = self.main.osm
        if not osm:
            return

        out("Neighbor Nodes: {direction, ipp, ping, nick}")

        nbs = list(osm.pgm.inbound | osm.pgm.outbound)

        for n in nbs:
            iwant = (n in osm.pgm.outbound)
            uwant = (n in osm.pgm.inbound)

            info = []

            if iwant and uwant:
                info.append("<->")
            elif iwant:
                info.append("-->")
            elif uwant:
                info.append("<--")

            info.append(binascii.hexlify(n.ipp).upper())

            if n.avg_ping is not None:
                delay = n.avg_ping * 1000.0
            else:
                delay = 0.0
            info.append("%7.1fms" % delay)

            info.append("(%s)" % n.nick)

            out(' '.join(info))


    def debug_nodes(self, out, sortkey):

        osm = self.main.osm
        if not (osm and osm.syncd):
            out("Not syncd")
            return

        me = osm.me

        now = seconds()

        out("Online Nodes: {ipp, nb, persist, expire, uptime, dttag, nick}")

        lines = []

        for n in ([me] + osm.nodes):
            info = []
            info.append(binascii.hexlify(n.ipp).upper())

            if n.is_ping_nb:
                info.append("Y")
            else:
                info.append("N")

            if n.persist:
                info.append("Y")
            else:
                info.append("N")

            if n is me:
                info.append("%4d" % dcall_timeleft(osm.sendStatus_dcall))
            else:
                info.append("%4d" % dcall_timeleft(n.expire_dcall))

            info.append("%8d" % (now - n.uptime))
            info.append("%8s" % n.dttag[3:])
            info.append("(%s)" % n.nick)

            lines.append(info)

        if 1 <= sortkey <= 7:
            lines.sort(key=lambda l: l[sortkey-1])

        for line in lines:
            out(' '.join(line))

