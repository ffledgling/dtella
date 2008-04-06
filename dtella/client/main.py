"""
Dtella - Client Main Module
Copyright (C) 2008  Dtella Labs (http://www.dtella.org/)
Copyright (C) 2008  Paul Marks (http://www.pmarks.net/)
Copyright (C) 2008  Jacob Feisley (http://www.feisley.com/)

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

import twisted.internet.error
from twisted.internet import reactor
import sys
import socket
import time
import random

import dtella.local_config as local
import dtella.common.core as core
import dtella.common.state
import dtella.client.pull_dconfig

if local.use_locations:
    from dtella.common.reverse_dns import ipToHostname

from dtella.common.util import (dcall_discard, Ad, word_wrap, get_user_path,
                                CHECK)
from dtella.common.log import LOG

STATE_FILE = "dtella.state"

class DtellaMain_Client(core.DtellaMain_Base):

    def __init__(self):
        core.DtellaMain_Base.__init__(self)

        # Location map: ipp->string, usually only contains 1 entry
        self.location = {}

        # This shuts down the Dtella node after a period of inactivity.
        self.disconnect_dcall = None

        # Login counter (just for eye candy)
        self.login_counter = 0
        self.login_text = ""

        # DC Handler(s)
        self.dch = None
        self.pending_dch = None

        # Nick used for passive-mode transfer aborting
        self.abort_nick = None

        # Peer Handler
        try:
            import dtella.client.bridge_client as bridge_client
        except ImportError:
            self.ph = core.PeerHandler(self)
        else:
            self.ph = bridge_client.BridgeClientProtocol(self)

        # State Manager
        self.state = dtella.common.state.StateManager(
            self, STATE_FILE, dtella.common.state.client_loadsavers)
        self.state.initLoad()

        # DNS Handler
        self.dcfg = dtella.client.pull_dconfig.DynamicConfigPuller(self)


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

        # Set a new UDP port, which will be used on the next bind.
        self.state.udp_port = udp_port
        self.state.saveState()

        udp_state = self.ph.getSocketState()

        if udp_state == 'alive':
            # Port is alive, so shutdown and kill it.  PeerHandler will
            # reconnect when it notices the port is gone.
            self.shutdown(reconnect='no')
            self.ph.transport.stopListening()

        elif udp_state == 'dying':
            # Port is dying, maybe because of a previous change request.
            # Just let the existing callbacks take care of it.
            pass

        else:
            # Port is already gone, so try reconnecting.
            CHECK(udp_state == 'dead')
            self.startConnecting()


    def bindUDPPort(self):
        # Returns True if the UDP port is bound

        udp_state = self.ph.getSocketState()

        if udp_state == 'alive':
            # Port already bound, yay!
            return True
        elif udp_state == 'dying':
            # Port is busy disconnecting.  Wait.
            return False

        # Otherwise, the port is dead, so try to rebind it.
        CHECK(udp_state == 'dead')

        try:
            reactor.listenUDP(self.state.udp_port, self.ph)

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

        return self.ph.getSocketState() == 'alive'


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

        self.dcfg.getDynamicConfig(dns_cb)


    def queryLocation(self, my_ipp):
        # Try to convert the IP address into a human-readable location name.
        # This might be slightly more complicated than it really needs to be.

        CHECK(local.use_locations)

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

            # Use local_config to transform this hostname into a
            # human-readable location
            loc = local.hostnameToLocation(hostname)

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
        ipToHostname(ad).addCallback(cb)


    def logPacket(self, text):
        dch = self.dch
        if dch and dch.bot.dbg_show_packets:
            dch.bot.say(text)


    def getBridgeManager(self):
        # Create BridgeClientManager, if the module exists
        try:
            import dtella.client.bridge_client as bridge_client
        except ImportError:
            return {}
        else:
            return {'bcm': bridge_client.BridgeClientManager(self)}


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

        # Cancel the dns update timer, and remove pending callback.
        self.dcfg.dtellaShutdown()


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
            self.dcfg.resetReportedVersion()
            self.dcfg.reportNewVersion()


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
        when = core.NO_CLIENT_TIMEOUT

        if self.disconnect_dcall:
            self.disconnect_dcall.reset(when)
            return

        def cb():
            self.disconnect_dcall = None
            self.shutdown(reconnect='no')

        self.disconnect_dcall = reactor.callLater(when, cb)
