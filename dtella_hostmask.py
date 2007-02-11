import md5
import struct
import array

# CE199B6D.6451427F.694F561.IP
# 71.149.196.10

from dtella_util import Ad

KEY1, KEY2, KEY3 = ["aoAr1HnR6gl3sJ7hVz4Zb7x4YwpW",
                    "sdj8h82kd9sJ76fskkaJUS83KAs9",
                    "jd8L3J837jjakde25Nkdor398smN"]

prefix = "dh"


def ipstr(ip):
    return '.'.join(["%d" % o for o in ip])


def split_ip(ip):
    return [int(o) for o in ip.split('.')]


def m(s):
    # MD5
    return md5.new(s).digest()


def d(in_str):
    # Downsample
    a = array.array('B', in_str)
    parts = ["%02X" % (a[i]^a[i+1]^a[i+2]^a[i+3]) for i in range(0,16,4)]
    return ''.join(parts)
   

def mask_hostname(host):
    alpha = d(m(m("%s:%s:%s" % (KEY1, host, KEY2)) + KEY3))

    out = "%s-%s" % (prefix, alpha)

    try:
        out += host[host.index('.'):]
    except ValueError:
        pass

    return out


def mask_ipv4(ip):
    ip = split_ip(ip)
    alpha = d(m(m("%s:%s:%s" % (KEY2, ipstr(ip[:4]), KEY3)) + KEY1))
    beta =  d(m(m("%s:%s:%s" % (KEY3, ipstr(ip[:3]), KEY1)) + KEY2))
    gamma = d(m(m("%s:%s:%s" % (KEY1, ipstr(ip[:2]), KEY2)) + KEY3))

    return "%s.%s.%s.IP" % (alpha, beta, gamma)



