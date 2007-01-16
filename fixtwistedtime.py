import time
import os
import twisted.python.runtime

# Twisted 2.4.0 uses the system time for firing events.  This could lead to
# really bad things if the user fiddles with their clock.

# This code should help until they actually fix Twisted.

if os.name == 'nt':
    # time.clock works nicely in Windows
    twisted.python.runtime.seconds = time.clock
else:
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
            tt = time.time()
            self.counter += min(60.0, max(0.0, tt-self.last))
            self.last = tt
            return self.counter
    
    twisted.python.runtime.seconds = NonDecreasingTimer().seconds

    # Ensure that seconds() gets called at least once a minute
    from twisted.internet import reactor

    def noop():
        reactor.callLater(55.0, noop)

    noop()


