"""
Dtella - Localization Module
Copyright (C) 2007  Paul Marks (www.pmarks.net)

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

# These settings are specific to the Purdue network.

version = "SVN"

network_key = 'PurdueDtella-10'

hub_name = "Dtella@Purdue"

dns_servers = ['4.2.2.1','4.2.2.2','208.67.220.220','208.67.222.222']
dnshost = 'purdue.config.dtella.org'

def validateIP(ip):
    # ip is a tuple of 4 integers (a, b, c, d)
    # Return True if the IP belongs to this site
    return ip[0] == 128 and ip[1] in (10,46,210,211)


use_locations = True

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

