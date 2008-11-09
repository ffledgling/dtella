"""
Dtella - Twisted Unb0rkification Module
Copyright (C) 2008  Dtella Labs (http://www.dtella.org)
Copyright (C) 2008  Paul Marks

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

import time
import os
import socket
import twisted.python.runtime

# WARNING: do not import any other Twisted libraries before patching
# the time source!

# Twisted uses the system time for firing events.  This could lead to
# really bad things if the user fiddles with their clock.

# This code should help until they actually fix Twisted.

class NonDecreasingTimer:
    # This class lets us count the time between events, whilst mostly
    # hiding the effect of large changes in the system clock.    
    def __init__(self):
        self.last = time.time()
        self.counter = 0.0

    def seconds(self):
        # This method should be called at least once per minute to
        # keep the timer going.  If the system time moves backwards,
        # the timer will stay put.  If the time moves forwards,
        # the timer will increment, but never by more than 1 minute.
        now = time.time()
        self.counter += min(60.0, max(0.0, now-self.last))
        self.last = now
        return self.counter
    
twisted.python.runtime.seconds = NonDecreasingTimer().seconds

# Ensure that seconds() gets called at least once a minute
from twisted.internet import reactor

def noop():
    reactor.callLater(55.0, noop)

noop()

# Tell doRead to ignore the socket errors that Windows likes to spew randomly.
def patchDoRead():
    from twisted.internet import udp
    f = udp.Port.doRead
    def f2(*args, **kw):
        try:
            return f(*args, **kw)
        except socket.error:
            pass
    udp.Port.doRead = f2

patchDoRead()

