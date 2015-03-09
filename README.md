Dtella
========================================

A distributed P2P system which emulates a Direct Connect hub, primarily for college 
campuses and other low-latency LANs, for more information see [http://dtella.org](http://dtella.org).


About this Repository
---------------------

This repository is a fork of [gnu-user/dtella](https://github.com/gnu-user/dtella) which is in turn
a fork of the [latest revision (r635)](https://code.google.com/p/dtella/source/detail?r=635) of
Dtella from the official SVN repository. The intent of this fork, like the other fork is to improve
upon the original Dtella implementation, investigate ways that it could be improved further and
additionally adapt it for local use.


Installing
----------

See [Install Instructions](https://github.com/ffledgling/dtella/blob/master/INSTALL.md)

After follwing the install instructions, follow the **Connecting to Dtella (connecting to local DCC hub)** section below (Step #3 onwards).


Connecting to Dtella (connecting to local DCC hub)
----------------------------------------
1. Open the DCC client

2. Start the dtella script

3. Add a new connection to your Client

4. Enter the name as anything you like

5. For the **Hub address** enter the loopback address followed by your dtella port in the format of `<ip_address>:<port>` e.g:

        127.0.0.1:7314

6. Save the connection

7. Connect to the newly created hub.


Connecting to Peers
----------------------------------------

You should be able to automatically connect to all Peers.
(This takes some time the first time you join the network)

If for whatever reason this does not work, you should be able to use the following command

        !addpeer <Peer's IP>:13337

The previous command will add the peer to your client (however it might take a while to refresh)

You can always re-connect to the hub (hit Ctrl-R in your DC client) to restart the peer search.

Peer Discovery Methods Supported
--------------------------------

In decreasing order of efficiency.

1. Google Spreadsheet
2. DNS
3. Multicast
4. Network Scan

TODO
----
- [ ] DTella page
- [ ] Clean up code
- [ ] Add better/faster P2P scanning
- [ ] Improve multicasing code
- [ ] Document differences clearly
- [ ] Expose debugging and configuration options via flags/bot commands
- [ ] Replace existing readboard with a distributed one (possibly by extending the DC protocol)

Additional Configuration Options
--------------------------------

This fork adds a couple of options to the original dtella configuration file, doucmented here:

- `force_scan`: A full Network Scan is a floody technique, it's used only when this option is set to `True`
- `default_udpport`: Used by Network Scan, set to `None` if you wish to use a random port like the original dtella instead.


Original README.md
==================

See README.md.old


Copyright (Really Copyleft)
----------------------------------------

All of the source code in this repository is licensed under the 
[GNU General Public License, Version 2](http://www.gnu.org/licenses/gpl2.html). All kudos
go to the original creators of Dtella, [Jacob Feisley](http://feisley.com), 
[Paul Marks](http://pmarks.net), and [Dtella Labs](http://dtella.org).

