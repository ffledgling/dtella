# Dtella site-specific configuration

network_key = 'PurdueDtella-test8'

dnshost = 'config.dtella.org'

def validateIP(ip):
    # ip is a tuple of 4 integers (a, b, c, d)
    # Return True if the IP belongs to this site
    return ip[0] == 128 and ip[1] in (10,46,210,211)

