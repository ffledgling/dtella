#!/usr/bin/env python

"""
Dtella - Node Startup Module
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

import dtella_core
import twisted.internet.error
import twisted.python.log
from twisted.internet import reactor
import sys
import socket
import time

import dtella_state
import dtella_dc
import dtella_dnslookup
import dtella_local

from dtella_util import dcall_discard, Ad, word_wrap

tcp_port = 7314
STATE_FILE = "dtella.state"


class DtellaMain_Client(dtella_core.DtellaMain_Base):

    def __init__(self):
        dtella_core.DtellaMain_Base.__init__(self)

        # Location map: ipp->string, usually only contains 1 entry
        self.location = {}

        # This shuts down the Dtella node after a period of inactivity.
        self.disconnect_dcall = None

        # Login counter (just for eye candy)
        self.login_counter = 0
        self.login_text = ""

        # Synchronization stuff
        self.blockers = set()
        self.changing_port = False

        # DC Handler(s)
        self.dch = None
        self.pending_dch = None

        # Nick used for passive-mode transfer aborting
        self.abort_nick = None

        # Peer Handler
        try:
            import dtella_bridgeclient
        except ImportError:
            self.ph = dtella_core.PeerHandler(self)
        else:
            self.ph = dtella_bridgeclient.BridgeClientProtocol(self)

        # State Manager
        self.state = dtella_state.StateManager(self, STATE_FILE)

        # DNS Handler
        self.dnsh = dtella_dnslookup.DNSHandler(
            self, dtella_local.dns_servers)

        # Hold off on binding the UDP port until we get the TCP port
        self.addBlocker('udp_bind')


    def connectionPermitted(self):

        if self.blockers:
            return False

        if not (self.dch or self.state.persistent):
            return False

        return True


    def cleanupOnExit(self):
        print "Reactor is shutting down.  Doing cleanup."
        if self.dch:
            self.dch.state = 'shutdown'
        self.shutdown(reconnect='no')
        self.state.saveState()


    def addBlocker(self, name):
        # Add a blocker.  Connecting will be prevented until the
        # blocker is removed.
        self.blockers.add(name)
        self.shutdown(reconnect='no')


    def removeBlocker(self, name):
        # Remove a blocker
        self.blockers.remove(name)

        # Start connecting, if there's a reason to.
        if self.connectionPermitted():
            self.newConnectionRequest()


    def changeUDPPort(self, udp_port):
        # Shut down the node, and start up with a different UDP port

        # Pseudo-mutex: can't change the port twice simultaneously
        if self.changing_port:
            return False

        self.changing_port = True

        self.state.udp_port = udp_port
        self.state.saveState()

        def cb(result):
            self.bindUDPPort()
            self.changing_port = False

        self.unbindUDPPort(cb)
        return True


    def bindUDPPort(self):

        # This blocker should be set iff the udp port isn't bound already
        if 'udp_bind' not in self.blockers:
            return False

        try:
            reactor.listenUDP(self.state.udp_port, self.ph)
            self.removeBlocker('udp_bind')

        except twisted.internet.error.BindError:

            self.showLoginStatus("*** FAILED TO BIND UDP PORT ***")

            text = (
                "Dtella was not able to listen on UDP port %d. One possible "
                "reason for this is that you've tried to make your DC "
                "client use the same UDP port as Dtella. Two programs "
                "are not allowed listen on the same port.  To tell Dtella "
                "to use a different port, type !UDP followed by a number. "
                "Note that if you have a firewall or router, you will have "
                "to tell it to let traffic through on this port."
                % self.state.udp_port
                )

            for line in word_wrap(text):
                self.showLoginStatus(line)


    def unbindUDPPort(self, cb):
        # Release the UDP port, and call cb when done
        
        if 'udp_bind' in self.blockers:
            # Not bound yet
            reactor.callLater(0, cb, None)

        else:
            self.addBlocker('udp_bind')
            self.ph.transport.stopListening().addCallback(cb)
            

    def newConnectionRequest(self):
        # This fires when the DC client connects and wants to be online

        if self.icm or self.osm:
            # Already in progress; return description.
            return self.login_text

        self.login_text = ""

        # If we don't have the UDP port, then try again now.
        if self.bindUDPPort():
            return

        # If an update is necessary, this will add a blocker
        self.dnsh.updateIfStale()

        # Start connecting now if there are no blockers
        self.startConnecting()


    def queryLocation(self, my_ipp):
        # Try to convert the IP address into a human-readable location name.
        # This might be slightly more complicated than it really needs to be.

        ad = Ad().setRawIPPort(my_ipp)
        my_ip = ad.getTextIP()

        skip = False
        for ip,loc in self.location.items():
            if ip == my_ip:
                skip = True
            elif loc:
                # Forget old entries
                del self.location[ip]

        # If we already had an entry for this IP, then don't start
        # another lookup.
        if skip:
            return

        # A location of None indicates that a lookup is in progress
        self.location[my_ip] = None

        def cb(hostname):
            
            # Use dtella_local to transform this hostname into a
            # human-readable location
            loc = dtella_local.hostnameToLocation(hostname)

            # If we got a location, save it, otherwise dump the
            # dictionary entry
            if loc:
                self.location[my_ip] = loc
            else:
                del self.location[my_ip]

            # Maybe send an info update
            if self.osm:
                self.osm.updateMyInfo()

        # Start lookup
        self.dnsh.ipToHostname(ad, cb)


    def logPacket(self, text):
        dch = self.dch
        if dch and dch.bot.dbg_show_packets:
            dch.bot.say(text)


    def getBridgeManager(self):
        # Create BridgeClientManager, if the module exists
        try:
            import dtella_bridgeclient
        except ImportError:
            return {}
        else:
            return {'bcm': dtella_bridgeclient.BridgeClientManager(self)}


    def showLoginStatus(self, text, counter=None):

        # counter can be:
        # - int: set the counter to this value
        # - 'inc': increment from the previous counter value
        # - None: don't show a counter

        if type(counter) is int:
            self.login_counter = counter
        elif counter == 'inc':
            self.login_counter += 1

        if counter is not None:
            # Prepend a number
            text = "%d. %s" % (self.login_counter, text)

            # Remember this for new DC clients
            self.login_text = text
        
        dch = self.dch
        if dch:
            dch.pushStatus(text)


    def shutdown_NotifyObservers(self):
        # Tell the DC Handler that we lost the peer connection
        if self.dch:
            self.dch.dtellaShutdown()


    def getOnlineDCH(self):
        # Return DCH, iff it's fully online.

        dch = self.dch

        if dch and dch.isOnline():
            return dch
        else:
            return None


    def getStateObserver(self):
        return self.getOnlineDCH()


    def addDCHandler(self, dch):
        self.dch = dch

        # Cancel the disconnect timeout
        dcall_discard(self, 'disconnect_dcall')

        # Start connecting, or get status of current connection
        text = self.newConnectionRequest()
        if text:
            dch.pushStatus(text)

        # If we're not hung up on anything, then notify the user
        # about new versions.
        if not self.blockers:
            self.dnsh.sendVersionMessage()


    def removeDCHandler(self, dch):
        # DC client has left.

        if self.pending_dch is dch:
            self.pending_dch = None
            return
        elif self.dch is not dch:
            return

        self.dch = None 

        if self.osm:
            # Announce the DC client's departure
            self.osm.updateMyInfo()

            # Cancel all nick-specific stuff
            for n in self.osm.nodes:
                n.nickRemoved()

        # If another handler is waiting, let it on.
        if self.pending_dch:
            self.pending_dch.attachMeToDtella()
            self.pending_dch = None
            return

        # Maybe skip the disconnect
        if self.state.persistent or not (self.icm or self.osm):
            return

        # Client left, so shut down in a while
        when = dtella_core.NO_CLIENT_TIMEOUT

        if self.disconnect_dcall:
            self.disconnect_dcall.reset(when)
            return

        def cb():
            self.disconnect_dcall = None
            self.shutdown(reconnect='no')

        self.disconnect_dcall = reactor.callLater(when, cb)


def run():

    dtMain = DtellaMain_Client()

    def logObserver(eventDict):
        if eventDict["isError"]:
            if eventDict.has_key('failure'):
                text = eventDict['failure'].getTraceback()
            else:
                text = " ".join([str(m) for m in eventDict["message"]]) + "\n"

            dch = dtMain.dch
            if dch:
                dch.bot.say("Something bad happened:\n" + text)
            else:
                sys.stderr.write(text)
                sys.stderr.flush()

    twisted.python.log.startLoggingWithObserver(logObserver, setStdout=False)

    dfactory = dtella_dc.DCFactory(dtMain, tcp_port)

    print "Dtella %s" % dtella_local.version

    def cb(first):
        try:
            reactor.listenTCP(tcp_port, dfactory, interface='127.0.0.1')
        except twisted.internet.error.CannotListenError:
            if first:
                print "TCP bind failed.  Killing old process..."
                if terminate():
                    print "Ok.  Sleeping..."
                    reactor.callLater(2.0, cb, False)
                else:
                    print "Kill failed.  Giving up."
                    reactor.stop()
            else:
                print "Bind failed again.  Giving up."
                reactor.stop()
        else:
            print "Listening on 127.0.0.1:%d" % tcp_port
            dtMain.bindUDPPort()

    cb(True)
    reactor.run()


def terminate():
    # Terminate another Dtella process on the local machine

    try:
        print "Sending Packet of Death..."
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', tcp_port))
        sock.sendall("$KillDtella|")
        sock.close()
    except socket.error:
        return False

    return True


if __name__=='__main__':

    if len(sys.argv) == 2 and sys.argv[1] == "--terminate":
        if terminate():
            # Give the other process time to exit first
            print "Sleeping..."
            time.sleep(2.0)
        print "Done."
    else:
        run()
