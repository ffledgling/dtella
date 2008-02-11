#!/usr/bin/env python

"""
Dtella - Startup Module
Copyright (C) 2007-2008  Dtella Labs (http://www.dtella.org/)
Copyright (C) 2007-2008  Paul Marks (http://www.pmarks.net/)
Copyright (C) 2007-2008  Jacob Feisley (http://www.feisley.com/)

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

# Patch the twisted bugs before doing anything else.
import dtella.common.fix_twisted

import twisted.internet.error
import twisted.python.log
from twisted.internet import reactor
import sys
import socket
import time
import getopt

from dtella.common.log import initLogger


def addTwistedErrorCatcher(handler):
    def logObserver(eventDict):
        if not eventDict['isError']:
            return
        try:
            text = eventDict['failure'].getTraceback()
        except KeyError:
            text = ' '.join(str(m) for m in eventDict['message'])
        handler(text)
    twisted.python.log.startLoggingWithObserver(logObserver, setStdout=False)


def runBridge():
    import dtella.bridge_config as cfg
    LOG = initLogger(cfg.file_base + ".log", 4<<20, 4)
    LOG.debug("Bridge Logging Manager Initialized")

    addTwistedErrorCatcher(LOG.critical)

    from dtella.bridge.main import DtellaMain_Bridge
    dtMain = DtellaMain_Bridge()
    
    if cfg.irc_server:
        from dtella.bridge.bridge_server import IRCFactory
        ifactory = IRCFactory(dtMain)
        if cfg.irc_ssl:
            from twisted.internet import ssl
            sslContext = ssl.ClientContextFactory()
            reactor.connectSSL(cfg.irc_server, cfg.irc_port, ifactory,
                               sslContext)
        else:
            reactor.connectTCP(cfg.irc_server, cfg.irc_port, ifactory)
    else:
        LOG.info("IRC is not enabled.")

    reactor.run()


def runDconfigPusher():
    import dtella.bridge_config as cfg
    LOG = initLogger(cfg.file_base + ".log", 4<<20, 4)
    LOG.debug("Dconfig Pusher Logging Manager Initialized")

    addTwistedErrorCatcher(LOG.critical)

    from dtella.bridge.push_dconfig_main import DtellaMain_DconfigPusher
    dtMain = DtellaMain_DconfigPusher()
    reactor.run()


def runClient(dc_port):
    #Logging for Dtella Client
    LOG = initLogger("dtella.log", 1<<20, 1)
    LOG.debug("Client Logging Manager Initialized")

    from dtella.client.main import DtellaMain_Client
    dtMain = DtellaMain_Client()

    def botErrorReporter(text):
        dch = dtMain.dch
        if dch:
            dch.bot.say(
                "Something bad happened.  If you have the latest version "
                "of Dtella, then you might want to email this to "
                "bugs@dtella.org so we'll know about it:\n" + text)

    addTwistedErrorCatcher(botErrorReporter)
    addTwistedErrorCatcher(LOG.critical)

    from dtella.client.dc import DCFactory
    dfactory = DCFactory(dtMain, dc_port)

    import dtella.local_config as local
    LOG.info("%s %s" % (local.hub_name, local.version))

    def cb(first):
        try:
            reactor.listenTCP(dc_port, dfactory, interface='127.0.0.1')
        except twisted.internet.error.CannotListenError:
            if first:
                LOG.warning("TCP bind failed.  Killing old process...")
                if terminate(dc_port):
                    LOG.info("Ok.  Sleeping...")
                    reactor.callLater(2.0, cb, False)
                else:
                    LOG.error("Kill failed.  Giving up.")
                    reactor.stop()
            else:
                LOG.error("Bind failed again.  Giving up.")
                reactor.stop()
        else:
            LOG.info("Listening on 127.0.0.1:%d" % dc_port)
            dtMain.startConnecting()

    reactor.callWhenRunning(cb, True)
    reactor.run()


def terminate(dc_port):
    # Terminate another Dtella process on the local machine
    
    try:
        print "Sending Packet of Death on port %d..." % dc_port
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('127.0.0.1', dc_port))
        sock.sendall("$KillDtella|")
        sock.close()
    except socket.error:
        return False

    return True


def main():
    # Parse command-line arguments
    allowed_opts = []
    usage_str = "Usage: %s" % sys.argv[0]

    try:
        import dtella.client
    except ImportError:
        pass
    else:
        usage_str += " [--port=#] [--terminate]"
        allowed_opts.extend(['port=', 'terminate'])

    try:
        import dtella.bridge
    except ImportError:
        pass
    else:
        usage_str += " [--bridge] [--dconfigpusher] [--makeprivatekey]"
        allowed_opts.extend(['bridge', 'dconfigpusher', 'makeprivatekey'])

    try:
        opts, args = getopt.getopt(sys.argv[1:], '', allowed_opts)
    except getopt.GetoptError:
        print usage_str
        return

    opts = dict(opts)

    if '--bridge' in opts:
        runBridge()
        return

    if '--dconfigpusher' in opts:
        runDconfigPusher()
        return

    if '--makeprivatekey' in opts:
        from dtella.bridge.private_key import makePrivateKey
        makePrivateKey()
        return

    # User-specified TCP port
    dc_port = 7314
    if '--port' in opts:
        try:
            dc_port = int(opts['--port'])
            if not (1 <= dc_port < 65536):
                raise ValueError
        except ValueError:
            print "Port must be between 1-65535"
            return

    # Try to terminate an existing process
    if '--terminate' in opts:
        if terminate(dc_port):
            # Give the other process time to exit first
            print "Sleeping..."
            time.sleep(2.0)
        print "Done."
        return

    runClient(dc_port)


if __name__=='__main__':
    main()

