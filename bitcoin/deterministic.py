from main import *
import hmac, hashlib

### Electrum wallets

def electrum_stretch(seed): return slowsha(seed)

# Accepts seed or stretched seed, returns master public key
def electrum_mpk(seed):
    if len(seed) == 32: seed = electrum_stretch(seed)
    return privkey_to_pubkey(seed)[2:]

# Accepts (seed or stretched seed), index and secondary index
# (conventionally 0 for ordinary addresses, 1 for change) , returns privkey
def electrum_privkey(seed,n,for_change=0):
    if len(seed) == 32: seed = electrum_stretch(seed)
    mpk = electrum_mpk(seed)
    offset = dbl_sha256(str(n)+':'+str(for_change)+':'+mpk.decode('hex'))
    return add_privkeys(seed, offset)

# Accepts (seed or stretched seed or master public key), index and secondary index
# (conventionally 0 for ordinary addresses, 1 for change) , returns pubkey
def electrum_pubkey(masterkey,n,for_change=0):
    if len(masterkey) == 32: mpk = electrum_mpk(electrum_stretch(masterkey))
    elif len(masterkey) == 64: mpk = electrum_mpk(masterkey)
    else: mpk = masterkey
    bin_mpk = encode_pubkey(mpk,'bin_electrum')
    offset = bin_dbl_sha256(str(n)+':'+str(for_change)+':'+bin_mpk)
    return add_pubkeys('04'+mpk,privtopub(offset))

# seed/stretched seed/pubkey -> address (convenience method)
def electrum_address(masterkey,n,for_change=0,version=0):
    return pubkey_to_address(electrum_pubkey(masterkey,n,for_change),version)

# Given a master public key, a private key from that wallet and its index,
# cracks the secret exponent which can be used to generate all other private
# keys in the wallet
def crack_electrum_wallet(mpk,pk,n,for_change=0):
    bin_mpk = encode_pubkey(mpk,'bin_electrum')
    offset = dbl_sha256(str(n)+':'+str(for_change)+':'+bin_mpk)
    return subtract_privkeys(pk, offset)

# Below code ASSUMES binary inputs and compressed pubkeys
# mainnet, testnet, mainnet-p2wsh, testnet-p2wsh
BIP32_PUBLIC  = ['\x04\x88\xb2\x1e', '\x04\x35\x87\xcf', '\x02\xaa\x7e\xd3', '\x02\x57\x54\x83']
BIP32_PRIVATE = ['\x04\x88\xad\xe4', '\x04\x35\x83\x94', '\x02\xaa\x7a\x99', '\x02\x57\x50\x48']


# BIP32 child key derivation
def raw_bip32_ckd(rawtuple, i):
    vbytes, depth, fingerprint, oldi, chaincode, key = rawtuple
    i = int(i)

    if vbytes in BIP32_PRIVATE:
        priv = key
        pub = privtopub(key)
    else:
        pub = key

    if i >= 2**31:
        if vbytes in BIP32_PUBLIC:
            raise Exception("Can't do private derivation on public key!")
        I = hmac.new(chaincode,'\x00'+priv[:32]+encode(i,256,4),hashlib.sha512).digest()
    else:
        I = hmac.new(chaincode,pub+encode(i,256,4),hashlib.sha512).digest()

    if vbytes in BIP32_PRIVATE:
        newkey = add_privkeys(I[:32]+'\x01',priv)
        fingerprint = bin_hash160(privtopub(key))[:4]
    if vbytes in BIP32_PUBLIC:
        newkey = add_pubkeys(compress(privtopub(I[:32])),key)
        fingerprint = bin_hash160(key)[:4]
    
    return (vbytes, depth + 1, fingerprint, i, I[32:], newkey)

def bip32_serialize(rawtuple):
    vbytes, depth, fingerprint, i, chaincode, key = rawtuple
    depth = chr(depth % 256)
    i = encode(i,256,4)
    chaincode = encode(hash_to_int(chaincode),256,32)
    keydata = '\x00'+key[:-1] if vbytes in BIP32_PRIVATE else key
    bindata = vbytes + depth + fingerprint + i + chaincode + keydata
    return changebase(bindata+bin_dbl_sha256(bindata)[:4],256,58)

def bip32_deserialize(data):
    dbin = changebase(data,58,256)
    if bin_dbl_sha256(dbin[:-4])[:4] != dbin[-4:]:
        raise Exception("Invalid checksum")
    vbytes = dbin[0:4]
    depth = ord(dbin[4])
    fingerprint = dbin[5:9]
    i = decode(dbin[9:13],256)
    chaincode = dbin[13:45]
    key = dbin[46:78]+'\x01' if vbytes in BIP32_PRIVATE else dbin[45:78]
    return (vbytes, depth, fingerprint, i, chaincode, key)

def raw_bip32_privtopub(rawtuple):
    vbytes, depth, fingerprint, i, chaincode, key = rawtuple
    header = BIP32_PUBLIC[BIP32_PRIVATE.index(vbytes)]
    return (header, depth, fingerprint, i, chaincode, privtopub(key))

def bip32_privtopub(data):
    return bip32_serialize(raw_bip32_privtopub(bip32_deserialize(data)))

def bip32_ckd(data,i):
    return bip32_serialize(raw_bip32_ckd(bip32_deserialize(data),i))

def bip32_master_key(seed, network='btc'):
    assert network in ('btc', 'testnet')
    headers = {'btc': BIP32_PRIVATE[0], 'testnet': BIP32_PRIVATE[1], 'btc-p2wsh': BIP32_PRIVATE[2], 'testnet-p2wsh': BIP32_PRIVATE[3]}
    header = headers.get(network)
    I = hmac.new("Bitcoin seed",seed,hashlib.sha512).digest()
    return bip32_serialize((header, 0, '\x00'*4, 0, I[32:], I[:32]+'\x01'))

def bip32_bin_extract_key(data):
    return bip32_deserialize(data)[-1]

def bip32_extract_key(data):
    return bip32_deserialize(data)[-1].encode('hex')

def bip32_get_network(xkey):
    try:
        vbyte = get_version_byte(xkey)
        header = chr(vbyte) + b58check_to_bin(xkey)[:3]
        if header in (BIP32_PUBLIC[0], BIP32_PRIVATE[0], BIP32_PUBLIC[2], BIP32_PRIVATE[2]):
            return 'btc'
        if header in (BIP32_PUBLIC[1], BIP32_PRIVATE[1], BIP32_PUBLIC[3], BIP32_PRIVATE[3]):
            return 'testnet' 
    except AssertionError, e:
        pass

# Exploits the same vulnerability as above in Electrum wallets
# Takes a BIP32 pubkey and one of the child privkeys of its corresponding privkey
# and returns the BIP32 privkey associated with that pubkey
def raw_crack_bip32_privkey(parent_pub,priv):
    vbytes, depth, fingerprint, i, chaincode, key = priv
    pvbytes, pdepth, pfingerprint, pi, pchaincode, pkey = parent_pub
    i = int(i)

    if i >= 2**31: raise Exception("Can't crack private derivation!")

    I = hmac.new(pchaincode,pkey+encode(i,256,4),hashlib.sha512).digest()

    pprivkey = subtract_privkeys(key,I[:32]+'\x01')

    return (vbytes, pdepth, pfingerprint, pi, pchaincode, pprivkey)

def crack_bip32_privkey(parent_pub,priv):
    dsppub = bip32_deserialize(parent_pub)
    dspriv = bip32_deserialize(priv)
    return bip32_serialize(raw_crack_bip32_privkey(dsppub,dspriv))
