# Dtella site-specific configuration
import re

network_key = 'PurdueDtella-10'

hub_name = "Dtella@Purdue"

dnshost = 'purdue.config.dtella.org'

def validateIP(ip):
    # ip is a tuple of 4 integers (a, b, c, d)
    # Return True if the IP belongs to this site
    return ip[0] == 128 and ip[1] in (10,46,210,211)


# Purude-specific location lookup stuff
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
    # return None if unsure.

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

    return None

