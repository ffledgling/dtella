import dtella_core
import twisted.internet.error
from twisted.internet import reactor

import dtella_state
import dtella_dc
import dtella_dnslookup
import dtella_local

from dtella_util import dcall_discard, Ad, word_wrap


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

        # DC Handler(s)
        self.dch = None
        self.pending_dch = None

        # Peer Handler
        try:
            import dtella_bridgeclient
        except ImportError:
            self.ph = dtella_core.PeerHandler(self)
        else:
            self.ph = dtella_bridgeclient.BridgeClientProtocol(self)

        # State Manager
        self.state = dtella_state.StateManager(self, 'dtella.state')

        # DNS Handler
        self.dnsh = dtella_dnslookup.DNSHandler(self)

        # Bind UDP Port
        self.bindUDPPort()

        if self.state.persistent:
            self.newConnectionRequest()


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
        self.shutdown(final=True)
        self.state.saveState()


    def addBlocker(self, name):
        # Add a blocker.  Connecting will be prevented until the
        # blocker is removed.
        self.blockers.add(name)
        self.shutdown()


    def removeBlocker(self, name):
        # Remove a blocker, and start connecting if there are no more left.
        self.blockers.remove(name)
        self.startConnecting()


    def changeUDPPort(self, udp_port):
        # Shut down the node, and start up with a different UDP port

        if 'udp_change' in self.blockers:
            return False

        self.addBlocker('udp_change')

        self.state.udp_port = udp_port
        self.state.saveState()

        def cb(result):
            self.bindUDPPort()
            self.removeBlocker('udp_change')

        if self.ph.transport:
            self.ph.transport.stopListening().addCallback(cb)
        else:
            reactor.callLater(0, cb, None)

        return True


    def bindUDPPort(self):
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
            
            if 'udp_bind' not in self.blockers:
                self.addBlocker('udp_bind')
        else:
            if 'udp_bind' in self.blockers:
                self.removeBlocker('udp_bind')
            

    def newConnectionRequest(self):
        # This fires when the DC client connects and wants to be online

        # Cancel the disconnect timeout
        dcall_discard(self, 'disconnect_dcall')

        if self.icm or self.osm:
            # Already connecting, just wait.
            return

        # If an update is necessary, this will add a blocker
        self.dnsh.updateIfStale()

        # If we don't have the UDP port, then try again now.
        if 'udp_bind' in self.blockers:
            self.bindUDPPort()
            return

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

            # This text will be remembered for new DC clients
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

        if not (self.osm and self.osm.syncd):
            return None
        
        if self.dch and self.dch.state=='ready':
            return self.dch

        return None


    def getStateObserver(self):
        return self.getOnlineDCH()


    def addDCHandler(self, dch):
        self.dch = dch

        oldtext = self.login_text
        self.login_text = ""

        self.newConnectionRequest()

        if self.osm and oldtext and not self.login_text:
            # The connection request didn't trigger any text, so show
            # the previous status to this new DC client.
            self.login_text = oldtext
            dch.pushStatus(oldtext)


    def removeDCHandler(self):
        # DC client has left.
        
        self.dch = None

        if self.osm:
            # Announce the DC client's departure
            self.osm.updateMyInfo()

            # Cancel all private message timeouts
            for n in self.osm.nodes:
                n.cancelPrivMsgs()

        # If another handler is waiting, let it on.
        if self.pending_dch:
            self.pending_dch.accept()
            return

        # Maybe skip the disconnect
        if self.state.persistent or not (self.icm or self.osm):
            return

        # Client left, so shut down in a while
        when = dtella_core.NO_CLIENT_TIMEOUT

        print "Shutting down in %d seconds." % when

        if self.disconnect_dcall:
            self.disconnect_dcall.reset(when)
            return

        def cb():
            self.disconnect_dcall = None
            self.shutdown()

        self.disconnect_dcall = reactor.callLater(when, cb)


if __name__=='__main__':
        
    dtMain = DtellaMain_Client()

    #def kill():
    #    print "20-sec timeout"
    #    reactor.stop()
    #reactor.callLater(20.0, kill)
    #import profile
    #profile.run('reactor.run()')

    tcp_port = 7314
    dfactory = dtella_dc.DCFactory(dtMain, tcp_port)
    reactor.listenTCP(tcp_port, dfactory, interface='127.0.0.1')

    print "Dtella Experimental %s" % dtella_core.VERSION
    print "Listening on 127.0.0.1:%d" % tcp_port
    reactor.run()
