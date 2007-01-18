from twisted.protocols.basic import LineOnlyReceiver
from twisted.internet.protocol import ServerFactory, Protocol
from twisted.internet import reactor

from dtella_util import Ad, validateNick
import dtella
import struct
import os



class DCHandler(LineOnlyReceiver):

    MAX_LENGTH = 2**20
    delimiter = '|'


    def __init__(self, main):
        self.main = main
        

    def connectionMade(self):
        self.transport.setTcpNoDelay(True)
        
        self.dispatch = {}
        self.info = ''
        self.nick = ''
        self.bot = DtellaBot(self, '*Dtella')
        self.addDispatch('$ValidateNick',   1, self.d_ValidateNick)
        self.addDispatch('$GetINFO',        2, self.d_GetInfo)
        self.addDispatch('$ConnectToMe',    2, self.d_ConnectToMe)
        self.addDispatch('$RevConnectToMe', 2, self.d_RevConnectToMe)
        self.addDispatch('$GetNickList',    0, self.d_GetNickList)
        self.addDispatch('$MyINFO',        -3, self.d_MyInfo)
        self.addDispatch('$Search',        -2, self.d_Search)
        self.addDispatch('$To:',           -5, self.d_PrivateMsg)
        self.addDispatch('',                0, self.d_KeepAlive)
        self.nicks = {}

        # ['login', 'ready', 'collision', 'kicked']
        self.state = 'login'

        self.sendLine("$Lock FOO Pk=BAR")
        self.sendLine("$HubName Dtella")

        self.main.addDCHandler(self)


    def connectionLost(self, reason):
        print "Connection lost:", reason
        self.main.removeDCHandler()


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
            fn(*args)


    def addDispatch(self, command, nargs, fn):
        self.dispatch[command] = (nargs, fn)


    def d_ValidateNick(self, nick):

        if self.state != 'login' or self.nick:
            self.pushStatus("ERROR: $ValidateNick may only be sent once during login.")
            self.transport.loseConnection()
            return

        reason = validateNick(nick)

        if reason:
            self.pushStatus("Your nick is invalid: %s" % reason)
            self.pushStatus("Please fix it and reconnect.  Goodbye.")
            self.transport.loseConnection()
            return

        self.addDispatch("<%s>" % nick, -1, self.d_PublicMsg)
        self.nick = nick
        
        self.pushHello(self.bot.nick)
        self.pushHello(self.nick)


    def d_GetInfo(self, nick, _):

        if nick == self.bot.nick:
            info = "Local Dtella Bot$ $Bot\x01$$0$"
            self.pushInfo(nick, info)
            return

        if nick == self.nick:
            if self.info:
                self.pushInfo(nick, self.info)
            return

        if not self.main.getOnlineDCH():
            return

        try:
            n = self.main.osm.nkm.nickmap[nick.lower()]
        except KeyError:
            return

        if n.nick and n.info:
            self.pushInfo(n.nick, n.info)
        

    def d_GetNickList(self):

        if not self.nick:
            self.pushStatus("ERROR: Must send $ValidateNick before $GetNickList.")
            self.transport.loseConnection()
            return

        # Me and the bot are ALWAYS online
        nicks = [self.bot.nick, self.nick]

        # Add in the Dtella nicks, if we're on.
        if self.main.getOnlineDCH():
            nicks = set(nicks)
            nicks.update(self.main.osm.nkm.getNickList())
            nicks = list(nicks)

        nicks.sort()

        self.sendLine("$NickList %s$$" % '$$'.join(nicks))
        self.sendLine("$OpList %s$$" % self.bot.nick)


    def split_info(self, info):
        # Split a MyINFO string
        # [0:'description<tag>', 1:' ', 2:'speed_', 3:'email', 4:'sharesize', 5:'']

        if info:
            info = info.split('$',6)
            if len(info) == 6:
                return info

        # Too many or too few parts
        raise ValueError


    def split_tag(self, desc):
        # Break 'description<tag>' into ('description','tag')
        tag = ''
        if desc[-1:] == '>':
            try:
                pos = desc.rindex('<')
                tag = desc[pos+1:-1]
                desc = desc[:pos]
            except ValueError:
                pass
        return desc, tag


    def d_MyInfo(self, _1, _2, info):

        if not self.nick:
            self.pushStatus("ERROR: Must send $ValidateNick before $MyInfo.")
            self.transport.loseConnection()
            return

        oldstate = self.state

        if self.state == 'login':
            self.state = 'ready'

        # Insert version and OS information into tag.
        try:
            info = self.split_info(info)
        except ValueError:
            return
        desc, tag = self.split_tag(info[0])
        if tag:
            info[0] = "%s<%s,Dt:%s(%s)>" % (desc, tag, dtella.VERSION, os.name)
        else:
            info[0] = "%s<Dt:%s(%s)>" % (desc, dtella.VERSION, os.name)
        info = '$'.join(info)

        #Insert Version and OS information into the description
        info = dtella.VERSION + " (" + os.name + ") " + info

        # Save my new info
        self.info = info

        # If we're on, send it
        if self.main.getOnlineDCH():
            self.main.osm.updateMyInfo()

        if oldstate == 'login' and self.state == 'ready':
            self.d_GetNickList()


    def d_Search(self, addr_string, search_string):
        # Send a search request

        print "Search: addr='%s' string='%s'" % (addr_string, search_string)

        if not self.main.getOnlineDCH():
            self.pushStatus("Search: Not online!")
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
        
        self.pushSearchRequest(osm.me.ipp, search_string)

        #self.sendLine("$SR someguy2 My Received Files\\03 - Teardrop.mp3\x055294332 1/1\x05TTH:EDHQFNLBKI5ATAICGCSJDYZQEWVUEHHH3SLLBIY (127.0.0.1:7314)")


    def d_PrivateMsg(self, nick, _1, _2, _3, text):
        if nick == self.bot.nick:
            self.bot.commandInput(text)
            return

        if not self.main.getOnlineDCH():
            return

        if len(text) > 10:
            shorttext = text[:10] + '...'
        else:
            shorttext = text

        def fail_cb():
            self.pushPrivMsg(
                nick,
                "*** Your message \"%s\" could not be delivered." % shorttext)

        try:
            n = self.main.osm.nkm.lookupNick(nick)
        except KeyError:
            fail_cb()
            return

        n.event_PrivateMessage(self.main, text, fail_cb)


    def d_ConnectToMe(self, nick, addr):

        osm = self.main.osm

        if not self.main.getOnlineDCH():
            return

        try:
            dc_ad = Ad().setTextIPPort(addr)
        except ValueError:
            return

        try:
            n = self.main.osm.nkm.lookupNick(nick)
        except KeyError:
            print "ConnectToMe: Nick not found"
            return

        def fail_cb():
            print "CA Failed"

        n.event_ConnectToMe(self.main, dc_ad.port, fail_cb)


    def d_RevConnectToMe(self, _, nick):

        osm = self.main.osm

        if not self.main.getOnlineDCH():
            return

        def fail_cb():
            print "CP Failed"

        try:
            n = self.main.osm.nkm.lookupNick(nick)
        except KeyError:
            print "ConnectToMe: Nick not found"
            return

        n.event_RevConnectToMe(self.main, fail_cb)


    def d_PublicMsg(self, text):

        if not self.main.getOnlineDCH():
            self.pushStatus("Chat: Not online!")
            return

        if len(text) > 1024:
            text = text[:1024-12] + ' [Truncated]'

        flags = 0

        # TODO: this checking could be factored to handle other commands
        if len(text) > 4 and text[:4].lower() in ('/me ','+me ','!me '):
            text = text[4:]
            flags |= dtella.SLASHME_BIT

        osm = self.main.osm

        packet = osm.mrm.broadcastHeader('CH', osm.me.ipp)
        packet.append(struct.pack('!I', osm.mrm.getPacketNumber_chat()))

        packet.append(osm.me.nickHash())
        packet.append(struct.pack('!BH', flags, len(text)))
        packet.append(text)

        osm.mrm.newMessage(''.join(packet), tries=4)

        # Echo back to the DC client
        if flags & dtella.SLASHME_BIT:
            nick = "*"
            text = "%s %s" % (osm.me.nick, text)
        else:
            nick = osm.me.nick

        self.pushChatMessage(nick, text)


    def d_KeepAlive(self):
        # Doesn't do much really
        self.sendLine('')


    def pushChatMessage(self, nick, text):
        self.sendLine("<%s> %s" % (nick, text))


    def pushInfo(self, nick, info):
        self.sendLine('$MyINFO $ALL %s %s' % (nick, info))


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

        
    def nickCollision(self):
        oldstate = self.state
        self.state = 'collision'

        if oldstate == 'ready':
            self.d_GetNickList()

        self.pushStatus("The nick '%s' is already in use on this network."
                        "  Please change your nick, or try again later."
                        % self.nick)


    def isProtectedNick(self, nick):
        return (nick.lower() in (self.nick.lower(), self.bot.nick.lower()))


    def event_AddNick(self, nick, ipp):
        if not self.isProtectedNick(nick):
            self.pushHello(nick)
    

    def event_RemoveNick(self, nick, reason):
        if not self.isProtectedNick(nick):
            self.pushQuit(nick)


    def event_UpdateInfo(self, nick, info):
        self.pushInfo(nick, info)


    def event_ChatMessage(self, nick, text, flags):
        if flags & dtella.NOTICE_BIT:
            self.pushChatMessage(("*N# %s" % nick), text)
        elif flags & dtella.SLASHME_BIT:
            self.pushChatMessage("*", "%s %s" % (nick, text))
        else:
            self.pushChatMessage(nick, text)


##############################################################################


class DCPurgatory(Protocol):
    # When a DC connection already exists, pass the next connection here


    def __init__(self, main):
        self.main = main


    def showStatus(self, text):
        self.transport.write("<*Dtella> %s|" % text)


    def connectionMade(self):
        # If another client is already waiting, reject immediately
        if self.main.pending_dch:
            self.showStatus("Dtella is busy with other DC connections"
                            " from your computer.  Goodbye.")
            return

        # Otherwise, set us as the pending_dch for a while
        self.transport.stopReading()
        self.main.pending_dch = self

        def cb():
            self.main.pending_dch = None
            self.showStatus("Nope, it didn't leave.  Goodbye.")
            self.transport.loseConnection()

        self.timeout_dcall = reactor.callLater(5.0, cb)

        self.showStatus("Another DC client is already using Dtella on this"
                        " computer.  Waiting 5 seconds for it to leave.")


    def connectionLost(self, reason):
        if self.main.pending_dch is self:
            self.main.pending_dch = None


    def accept(self):
        self.timeout_dcall.cancel()
        self.main.pending_dch = None

        self.showStatus("The other client left.  Resuming normal connection.")

        # Transplant this connection into a new DCHandler and fire it up
        p = DCHandler(self.main)
        p.factory = self.factory
        p.transport = self.transport
        p.transport.protocol = p
        p.transport.startReading()
        p.connectionMade()


##############################################################################


class DCFactory(ServerFactory):
    def __init__(self, main):
        self.main = main
        
    def buildProtocol(self, addr):
        if addr.host != '127.0.0.1':
            return None

        if not self.main.dch:
            p = DCHandler(self.main)
        else:
            p = DCPurgatory(self.main)

        p.factory = self
        return p


##############################################################################


class DtellaBot(object):
    # This holds the logic behind the "*Dtella" user

    def __init__(self, dch, nick):
        self.dch = dch
        self.main = dch.main
        self.nick = nick


    def say(self, txt):
        self.dch.pushPrivMsg(self.nick, txt)


    def commandInput(self, txt):
        cmd = txt.upper().split()

        if not cmd:
            return

        try:
            f = getattr(self, 'handleCmd_' + cmd[0])
        except AttributeError:
            self.say("Unknown command '%s'.  Try HELP." % cmd[0])
            return

        f(cmd[1:])

        
    def handleCmd_HELP(self, args):
        self.say("This is your local Dtella bot.  You can send messages here")
        self.say("to control the various features of Dtella.  For more")
        self.say("information on a specific command, say HELP followed by")
        self.say("one of the commands below:")
        self.say(" ")
        self.say("   UDPPORT - Change Dtella's UDP Port")
        self.say("   ADDPEER - Add the IP:Port of another peer")
        self.say("   REBOOT - Shut down and reconnect this node")
        self.say("   PERSISTENT - Enable/Disable persistent mode")
        self.say(" ")


    def handleCmd_REBOOT(self, args):
        self.say("Rebooting Node...")
        self.main.shutdown(final=True)
        
        self.main.enableCopyStatusToPM()
        self.main.newConnectionRequest()


    def handleCmd_UDPPORT(self, args):
        if len(args) == 1:
            try:
                port = int(args[0])
                if not 1 <= port <= 65535:
                    raise ValueError
            except ValueError:
                self.say("UDPPORT must be followed by a port number between 1 and 65535")
            else:
                if self.main.changeUDPPort(port):
                    self.say("UDP port has been changed to %d." % port)
                    self.main.enableCopyStatusToPM()
                else:
                    self.say("UDP port was not changed; busy.")
        else:
            self.say("Dtella is currently using UDP port %d" % self.main.state.udp_port)


    def handleCmd_ADDPEER(self, args):

        if len(args) == 1:
            try:
                ad = Ad().setTextIPPort(args[0])
                if ad.validate():
                    self.main.state.refreshPeer(ad, 0)
                    self.say("Added to peer cache: %s" % ad.getTextIPPort())

                    # Jump-start stuff if it's not already going
                    self.main.enableCopyStatusToPM()
                    self.main.newConnectionRequest()
                    return
                else:
                    self.say("That IP is not permitted on this network")
            except ValueError:
                pass

        self.say("ADDPEER must be followed by an IP:Port")

    def handleCmd_PERSISTENT(self, args):
        if len(args) == 0:
            if self.main.state.persistent:
                self.say("Persistent mode is currently ON."
                         "  Type PERSISTENT OFF to turn it off.")
            else:
                self.say("Persistent mode is currently OFF."
                         "  Type PERSISTENT ON to turn it on.")
            return

        if len(args) == 1:
            if args[0] == 'ON':
                self.say("Persistent mode is now ON.")
                self.main.state.persistent = True
                self.main.state.saveState()

                if self.main.osm:
                    self.main.osm.updateMyInfo()

                self.main.enableCopyStatusToPM()
                self.main.newConnectionRequest()
                return

            elif args[0] == 'OFF':
                self.say("Persistent mode is now OFF.")
                self.main.state.persistent = False
                self.main.state.saveState()

                if self.main.osm:
                    self.main.osm.updateMyInfo()
                return
                
        self.say("PERSISTENT must be followed by ON or OFF.")


