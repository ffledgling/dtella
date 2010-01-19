"""
Dtella - Bridge Main Module
Copyright (C) 2008  Dtella Labs (http://www.dtella.org/)
Copyright (C) 2008  Paul Marks (http://www.pmarks.net/)

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

from twisted.internet import reactor
import twisted.internet.error

import dtella.bridge_config as cfg
import dtella.common.core as core
import dtella.common.state
import dtella.bridge.bridge_server as bridge_server
import dtella.bridge.push_dconfig as push_dconfig
from dtella.common.util import CHECK
from dtella.common.log import LOG
from dtella.common.ipv4 import Ad


class DtellaMain_Bridge(core.DtellaMain_Base):

    def __init__(self):
        core.DtellaMain_Base.__init__(self)

        # State Manager
        self.state = dtella.common.state.StateManager(
            self, cfg.file_base + '.state',
            dtella.common.state.bridge_loadsavers)
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
        self.ph = bridge_server.BridgeServerProtocol(self)

        # Reverse DNS Manager
        self.rdns = bridge_server.ReverseDNSManager(self)

        # DNS Update Manager
        self.dum = push_dconfig.DynamicConfigUpdateManager(self)

        # IRC State Manager
        self.ism = None

        self.startConnecting()


    def cleanupOnExit(self):
        LOG.info("Reactor is shutting down.  Doing cleanup.")

        self.shutdown(reconnect='no')
        self.state.saveState()

        # Cleanly close the IRC connection before terminating
        if self.ism:
            return self.ism.shutdown()


    def startConnecting(self):
        udp_state = self.ph.getSocketState()
        if udp_state == 'dead':
            bind_ip = bridge_server.getBindIP()
            try:
                reactor.listenUDP(cfg.udp_port, self.ph, interface=bind_ip)
            except twisted.internet.error.BindError:
                LOG.error("Failed to bind UDP port!")
                raise SystemExit
        elif udp_state == 'dying':
            return
        
        CHECK(self.ph.getSocketState() == 'alive')
        self.startInitialContact()


    def reconnectDesired(self):
        return True


    def getBridgeManager(self):
        return {'bsm': bridge_server.BridgeServerManager(self)}


    def logPacket(self, text):
        #print "pkt: %s" % text
        pass


    def showLoginStatus(self, text, counter=None):
        LOG.info(text)


    def queryLocation(self, my_ipp):
        pass


    def afterShutdownHandlers(self):
        pass


    def getOnlineDCH(self):
        # BridgeServer has no DC Handler
        return None


    def getStateObserver(self):
        # Return the IRC Server, iff it's fully online

        if not (self.osm and self.osm.syncd):
            return None

        if self.ism:
            return self.ism

        return None


    def addIRCStateManager(self, ism):
        CHECK(not self.ism)
        CHECK(ism.syncd)
        self.ism = ism
        self.stateChange_ObserverUp()


    def removeIRCStateManager(self, ism):
        CHECK(ism and (self.ism is ism))

        self.ism = None

        # Send empty IRC state to Dtella.
        self.stateChange_ObserverDown()

        osm = self.osm
        if osm:
            # Rebuild ban table.
            osm.banm.scheduleRebuildBans()

