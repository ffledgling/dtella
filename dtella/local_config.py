"""
Dtella - Local Site Configuration
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

# These settings are specific to the Purdue network.  They should be
# customized for each new network you create.

# When building an exe or installer, use this prefix, followed by the
# version number.
build_prefix = "dtella-purdue-"

# Dtella version number.
version = "SVN"

# This is an arbitrary string which is used for encrypting packets.
# It essentially defines the uniqueness of a Dtella network, so every
# network should have its own unique key.
network_key = 'PurdueDtella-11'

# This is the name of the "hub" which is seen by the user's DC client.
# "Dtella@____" is the de-facto standard, but nobody's stopping you
# from picking something else.
hub_name = "Dtella@Purdue"

# This enforces a maximum cap for the 'minshare' value which appears in DNS.
# It should be set to some sane value to prevent the person managing DNS from
# setting the minshare to 99999TiB, and effectively disabling the network.
minshare_cap = 100 * (1024**3)   # (=100GiB)

# This is a list of subnets (in CIDR notation) which will be permitted on
# the network.  Make sure you get this right initially, because you can't
# make changes once the program has been distributed.  In the unlikely event
# that you don't want any filtering, use ['0.0.0.0/0']
allowed_subnets = ['128.210.0.0/15', '128.10.0.0/16', '128.46.0.0/16']

# Here we configure an object which pulls 'Dynamic Config' from some source
# at a known fixed location on the Internet.  This config contains a small
# encrypted IP cache, version information, minimum share, and a hash of the
# IRC bridge's public key.

# -- Use DNS TXT Record --
import dtella.modules.pull_dns
dconfig_puller = dtella.modules.pull_dns.DnsTxtPuller(
    # Some public DNS servers to query through. (GTE and OpenDNS)
    servers = ['4.2.2.1','4.2.2.2','208.67.220.220','208.67.222.222'],
    # Hostname where the DNS TXT record resides.
    hostname = "purdue.config.dtella.org"
    )

# -- Use Google Spreadsheet --
##import dtella.modules.pull_gdata
##dconfig_puller = dtella.modules.pull_gdata.GDataPuller(
##    sheet_key = "..."
##    )

# Enable this if you can devise a meaningful mapping from a user's hostname
# to their location.  Locations are displayed in the "Connection / Speed"
# column of the DC client.
use_locations = True

###############################################################################

# if use_locations is True, then rdns_servers and hostnameToLocation will be
# used to perform the location translation.  If you set use_locations = False,
# then you may delete the rest of the lines in this file.

# DNS servers which will be used for doing IP->Hostname reverse lookups.
# These should be set to your school's local DNS servers, for efficiency.
rdns_servers = ['128.210.11.5','128.210.11.57','128.10.2.5','128.46.154.76']

# Customized data for our implementation of hostnameToLocation
import re
suffix_re = re.compile(r".*\.([^.]+)\.purdue\.edu")
prefix_re = re.compile(r"^([a-z]{1,6}).*\.purdue\.edu")

pre_table = {
    'erht':'Earhart', 'cary':'Cary', 'hill':'Hillenbrand',
    'shrv':'Shreve', 'tark':'Tarkington', 'wily':'Wiley',
    'mrdh':'Meredith', 'wind':'Windsor', 'harr':'Harrison',
    'hawk':'Hawkins', 'mcut':'McCutcheon', 'owen':'Owen',
    'hltp':'Hilltop', 'yong':'Young', 'pvil':'P.Village',
    'pal':'AirLink', 'dsl':'DSL', 'vpn':'VPN'}

suf_table = {
    'cerias':'CERIAS', 'cs':'CS', 'ecn':'ECN', 'hfs':'HFS',
    'ics':'ITaP Lab', 'lib':'Library', 'mgmt':'Management',
    'uns':'News', 'cfs':'CFS'}

def hostnameToLocation(hostname):
    # Convert a hostname into a human-readable location name.

    if hostname:

        suffix = suffix_re.match(hostname)
        if suffix:
            try:
                return suf_table[suffix.group(1)]
            except KeyError:
                pass
        
        prefix = prefix_re.match(hostname)
        if prefix:
            try:
                return pre_table[prefix.group(1)]
            except KeyError:
                pass

    return "Unknown"

