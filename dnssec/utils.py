"""DNSSEC utility functions. """

import hashlib
import dns.name
import dns.resolver

def make_owner(zone_name):
    return dns.name.from_text(zone_name, origin=dns.name.root)
    
def get_dnskeys(zone_name, nameservers=None):
    """Get DNSKEY records for a given zone"""
    resolver = dns.resolver.Resolver()
    if nameservers:
        resolver.nameservers = resolvers
    owner = make_owner(zone_name) 
    dnskeys = resolver.query(owner, 'DNSKEY', tcp=True)
    return dnskeys

def keytag(dnskey):
    """
    Given a dns.rdtypes.ANY.DNSKEY, compute and return its keytag.
    
    See rfc2535 section 4.1.6 for details.
    """
    if dnskey.algorithm == 1:
        a = ord(dnskey.key[-3]) << 8
        b = ord(dnskey.key[-2])
        return a + b
    else:
        key = dnskey.to_digestable()
        ac = 0
        for i, value in enumerate(ord(x) for x in key):
            if i % 2:
                ac += value
            else:
                ac += (value << 8)
        ac += (ac >> 16) & 0xffff
        return ac & 0xffff

def keytags(dnskeys):
    """Return keytags of dnskeys"""
    res = []
    for dnskey in dnskeys:
        res.append(keytag(dnskey))
    return res

_SHA_METHODS = {
    'sha-1' : hashlib.sha1,
    'sha-256' : hashlib.sha256,
}

def is_zsk(dnskey):
    return dnskey.flags == 256

def is_ksk(dnskey):
    return dnskey.flags == 257

def make_ds(zone_name, dnskeys, algorithm='sha-1'):
    """
    Given a zone name and a sequence of DNSKEYs return
    sequence of DS records of the Key Signing Keys.
    """
    ksks = [key for key in dnskeys if is_ksk(key)]

    sha_method = _SHA_METHODS.get(algorithm.lower())
    if sha_method is None:
        raise ValueError("Unknown Digest Algorithm")

    res = []
    owner = make_owner(zone_name) 
    for key in ksks:
        data = owner.to_wire() + key.to_digestable()
        sha = sha_method(data).hexdigest()
        res.append(sha)
    return res


if __name__ == '__main__':
    import sys
    try:
        zone_name = sys.argv[1]
    except IndexError:
        zone_name = 'edu.' 

    keys = get_dnskeys(zone_name)
    keytags = keytags(keys)
    sha1s = make_ds(zone_name, keys)
    sha256s = make_ds(zone_name, keys, algorithm='sha-256')
