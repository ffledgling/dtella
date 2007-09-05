#!/usr/bin/env python

"""
Dtella - Node Startup Module
Copyright (C) 2007  Dtella Labs (http://www.dtella.org/)
Copyright (C) 2007  Paul Marks (http://www.pmarks.net/)
Copyright (C) 2007  Jacob Feisley (http://www.feisley.com/)

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
import random

import dtella_state
import dtella_dc
import dtella_dnslookup
import dtella_local

import dtella_log

from dtella_util import dcall_discard, Ad, word_wrap, get_user_path, CHECK

tcp_port = 7314
STATE_FILE = "dtella.state"

#Logging for Dtella Client
LOG = dtella_log.makeLogger("dtella.client.log", 1048576, 1)
LOG.debug("Client Logging Manager Initialized")

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

        # Port state stuff
        self.changing_port = False
        self.udp_bound = False

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
        self.state = dtella_state.StateManager(
            self, STATE_FILE, dtella_state.client_loadsavers)
        self.state.initLoad()

        # DNS Handler
        self.dnsh = dtella_dnslookup.DNSHandler(self)


    def reconnectDesired(self):
        return (self.dch or self.state.persistent)


    def cleanupOnExit(self):
        LOG.info("Reactor is shutting down.  Doing cleanup.")
        if self.dch:
            self.dch.state = 'shutdown'
        self.shutdown(reconnect='no')
        self.state.saveState()


    def changeUDPPort(self, udp_port):
        # Shut down the node, and start up with a different UDP port

        # Pseudo-mutex: can't change the port twice simultaneously
        if self.changing_port:
            return False

        self.changing_port = True

        self.state.udp_port = udp_port
        self.state.saveState()

        def cb(result):
            self.changing_port = False
            self.startConnecting()

        self.unbindUDPPort(cb)
        return True


    def bindUDPPort(self):
        # Returns True if the UDP port is bound

        if self.udp_bound:
            return True

        try:
            reactor.listenUDP(self.state.udp_port, self.ph)
            self.udp_bound = True

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

        return self.udp_bound


    def unbindUDPPort(self, cb):
        # Release the UDP port, and call cb when done

        if self.udp_bound:
            self.shutdown(reconnect='no')
            self.udp_bound = False
            self.ph.transport.stopListening().addCallback(cb)

        else:
            # Not bound yet, just do the callback
            reactor.callLater(0, cb, None)


    def startConnecting(self):
        # This fires when the DC client connects and wants to be online

        dcall_discard(self, 'reconnect_dcall')

        # Only continue if the UDP port is ready
        if not self.bindUDPPort():
            return

        # Any reason to be online?
        if not self.reconnectDesired():
            return

        if self.icm or self.osm:
            # Already in progress; return description.
            return self.login_text

        # Get config from DNS
        def dns_cb():
            try:
                when, ipps = self.state.dns_ipcache
            except ValueError:
                pass
            else:
                random.shuffle(ipps)
                age = max(time.time() - when, 0)
                for ipp in ipps:
                    ad = Ad().setRawIPPort(ipp)
                    self.state.refreshPeer(ad, age)

            self.startInitialContact()

        self.dnsh.getConfigFromDNS(dns_cb)


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
        dtella_dnslookup.ipToHostname(ad, cb)


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
        
        LOG.debug(text)
        dch = self.dch
        if dch:
            dch.pushStatus(text)


    def shutdown_NotifyObservers(self):
        # Tell the DC Handler that we lost the peer connection
        if self.dch:
            self.dch.dtellaShutdown()

        # Cancel the dns update timer
        self.dnsh.dtellaShutdown()


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

        CHECK(not self.dch)
        
        self.dch = dch

        # Cancel the disconnect timeout
        dcall_discard(self, 'disconnect_dcall')

        # Start connecting, or get status of current connection
        text = self.startConnecting()
        if text:
            # We must already be connecting/online.
            # Show the last status message.
            LOG.debug(text)
            dch.pushStatus(text)

            # Send a message if there's a newer version
            self.dnsh.resetReportedVersion()
            self.dnsh.reportNewVersion()


    def removeDCHandler(self, dch):
        # DC client has left.

        if self.pending_dch is dch:
            self.pending_dch = None
            return
        elif self.dch is not dch:
            return

        self.dch = None
        self.abort_nick = None

        if self.osm:
            # Announce the DC client's departure
            self.osm.updateMyInfo()

            # Cancel all nick-specific stuff
            for n in self.osm.nodes:
                n.nickRemoved(self)

        # If another handler is waiting, let it on.
        if self.pending_dch:
            self.pending_dch.attachMeToDtella()
            self.pending_dch = None
            return

        # Maybe forget about reconnecting
        if not self.reconnectDesired():
            dcall_discard(self, 'reconnect_dcall')

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
                LOG.critical(text)
                dch.bot.say(
                    "Something bad happened.  If you have the latest version "
                    "of Dtella, then you might want to email this to "
                    "bugs@dtella.org so we'll know about it:\n" + text)
            else:
                LOG.critical(text)


    twisted.python.log.startLoggingWithObserver(logObserver, setStdout=False)

    dfactory = dtella_dc.DCFactory(dtMain, tcp_port)
    
    LOG.info("Dtella %s" % dtella_local.version)

    def cb(first):
        try:
            reactor.listenTCP(tcp_port, dfactory, interface='127.0.0.1')
        except twisted.internet.error.CannotListenError:
            if first:
                LOG.warning("TCP bind failed.  Killing old process...")
                if terminate():
                    LOG.info("Ok.  Sleeping...")
                    reactor.callLater(2.0, cb, False)
                else:
                    LOG.error("Kill failed.  Giving up.")
                    reactor.stop()
            else:
                LOG.error("Bind failed again.  Giving up.")
                reactor.stop()
        else:
            LOG.info("Listening on 127.0.0.1:%d" % tcp_port)
            dtMain.startConnecting()

    cb(True)
    reactor.run()


def terminate():
    # Terminate another Dtella process on the local machine
    
    try:
        LOG.info("Sending Packet of Death...")
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
            LOG.info("Sleeping...")
            time.sleep(2.0)
        LOG.info("Done.")
    else:
        run()
