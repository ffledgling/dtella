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


Installing
----------

See [Install Instructions](https://github.com/ffledgling/dtella/blob/master/INSTALL.md)

After follwing the install instructions, follow the **Connecting to Dtella (connecting to local DCC hub)** section below (Step #3 onwards).

---------------------


Additional Configuration Options
--------------------------------

This fork adds a couple of options to the original dtella configuration file, doucmented here:

- `force_scan`: A full Network Scan is a floody technique, it's used only when this option is set to `True`
- `default_udpport`: Used by Network Scan, set to `None` if you wish to use a random port like the original dtella instead.



Original README.md
==================

Everything beyond this section is from the original README, it may or may not
be accurate. It stays here for historical purposes and till I get around to
writing a better README.

***End of section***

Setting up Dtella
------------------

### Ubuntu

Look at the [setup](setup) value in order to install.

### Windows

#### Running

If you are using the *exe* you do not need to worry about installing the dependencies since they are including in the *exe*.

#### Creating the EXE

1. Install 7zip

2. Install nsis

##### Install Python

1. Install python2.7

2. Install py2exe

3. Install Twisted

4. Install Zope (version 3.6 or higher)

5. Fix Zope install by adding the a empty file `__init__.py`, in `C:\<PYTHON_DIR>\Lib\site-packages\zope\`

6. Install pycrypto

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

8. Enter the command to set the UDP port for connecting to other clients e.g:

        !UDP 32421

Connecting to Peers
----------------------------------------
**Please note** you must already be connected to the local hub.

1. Find out a peer's `local ip address` and `dtella port` (they must also complete the above section) e.g:

        10.121.90.81:32421

2. In the DC++ chat enter `!addpeer` command along with the `local ip address` and the dtella port (found in the previous step) e.g:

        !addpeer 10.121.90.81:32421

3. The previous command will add the peer to your client (however it might take a while to refresh)

4. Alternatively you can use `!findpeers` to locate peers on your local network. (This also sometimes helps with the client list refresh)

IRC bot
----------------------------------------
The configuration fields include:
* bot_name, must be a valid irc name
* bot_nickname, must be a valid irc nick
* irc_server, the domain name of the irc server (e.g. example.com)
* channel, the channel to auto join. This must be a valid channel name, note channel may require a *#* at the beginning, in order to add the *#* you must surround the word with single quotes. Alternatively, you can leave it empty for no auto join.
* irc_port, the port to connect to the irc, must be a valid port
* owner, your name, nick name, can be left empty
* dtella_port, the port that dtella is running on
* secret, whether to run in secret mode or not

### Running the irc bot

**Please Note** the bot does not require dtella to be running or for you to be connected to your hub. However, if you are not running dtella and connected to your hub users will not be able to connect and therefore running this bot will be a little redundent.

1. Adjust the above define configurations as desired to work with local hub peers

2. Install the bundler gem

        sudo gem install bundler

3. Run the bundler:

        bundle install

4. Start the bot

        ruby bot.rb


Project Goals
----------------------------------------

* To find an alternative to the dependency on a centralized DNS TXT or external Google doc and
  investigate making it truly redundant and de-centralized.
* Improve the creation of insallers and create one-click installers that makes it easy to
  use Dtella with an already pre-configured client for Windows, OS X, and Linux.
* Investigate improving the mesh network and DHT implementation.


Copyright (Really Copyleft)
----------------------------------------

All of the source code in this repository is licensed under the 
[GNU General Public License, Version 2](http://www.gnu.org/licenses/gpl2.html). All kudos
go to the original creators of Dtella, [Jacob Feisley](http://feisley.com), 
[Paul Marks](http://pmarks.net), and [Dtella Labs](http://dtella.org).

