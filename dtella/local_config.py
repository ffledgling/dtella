# These settings are specific to the Purdue network.  They should be
# customized for each new network you create.

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

# Public DNS servers, which will be used to query config.
dns_servers = ['4.2.2.1','4.2.2.2','208.67.220.220','208.67.222.222']

# DNS address where the config TXT record resides.
# This usually contains a small encrypted IP cache, version information,
# minimum share, and a hash of the IRC bridge's public key.
dnshost = 'purdue.config.dtella.org'

# DNS servers which will be used for doing IP->Hostname reverse lookups.
# These should be set to your school's local DNS servers.  If for some reason
# your network isn't localized, you could set rnds_servers = dns_servers.
rdns_servers = ['128.210.11.5','128.210.11.57','128.10.2.5','128.46.154.76']

# This function should examine an IP address, and return True if it's
# permitted on the network, False otherwise.  Since this is called for every
# packet, it should be as fast as possible.
# (You may want to consult a CS major who's familiar with Python.)
def validateIP(ip):
    # ip is a tuple of 4 integers (a, b, c, d)
    return ip[0] == 128 and ip[1] in (10,46,210,211)

# Enable this if you can devise a meaningful mapping from a user's hostname
# to their location.  Locations are displayed in the "Connection / Speed"
# column of the DC client.
use_locations = True

# if use_locations is True, then hostnameToLocation will be called to perform
# the location translation.  If you set use_locations = False, then
# hostnameToLocation will never be called, and you may delete the rest of
# the lines in this file.

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

