#!/usr/bin/python
import hashlib, re, sys, os, base64, time, random, hmac
import ripemd
import binascii
import ctypes
import ctypes.util

lib = ctypes.util.find_library('libsecp256k1') or ctypes.util.find_library('secp256k1')
assert lib, 'failed to find libsecp256k1'
sipa = ctypes.cdll.LoadLibrary(lib)
assert sipa, 'failed to load libsecp256k1'
sipa.secp256k1_start(0b11)

### Elliptic curve parameters (secp256k1)

P = 2**256-2**32-2**9-2**8-2**7-2**6-2**4-1
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337
A = 0
B = 7
Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240
Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424
G = (Gx,Gy)


def change_curve(p, n, a, b, gx, gy):
    global P, N, A, B, Gx, Gy, G
    P, N, A, B, Gx, Gy = p, n, a, b, gx, gy
    G = (Gx, Gy)

def getG():
    return G

### Extended Euclidean Algorithm

def inv(a,n):
    lm, hm = 1,0
    low, high = a%n,n
    while low > 1:
        r = high/low
        nm, new = hm-lm*r, high-low*r
        lm, low, hm, high = nm, new, lm, low
    return lm % n

### Base switching

def get_code_string(base):
    if base == 2: return '01'
    elif base == 10: return '0123456789'
    elif base == 16: return '0123456789abcdef'
    elif base == 32: return 'abcdefghijklmnopqrstuvwxyz234567'
    elif base == 58: return '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    elif base == 256: return ''.join([chr(x) for x in range(256)])
    else: raise ValueError("Invalid base!")

def lpad(msg,symbol,length):
    if len(msg) >= length: return msg
    return symbol * (length - len(msg)) + msg

def encode(val,base,minlen=0):
    base, minlen = int(base), int(minlen)
    code_string = get_code_string(base)
    result = ""   
    while val > 0:
        result = code_string[val % base] + result
        val /= base
    return lpad(result,code_string[0],minlen)

def decode(string,base):
    base = int(base)
    code_string = get_code_string(base)
    result = 0
    if base == 16: string = string.lower()
    while len(string) > 0:
        result *= base
        result += code_string.find(string[0])
        string = string[1:]
    return result

def changebase(string,frm,to,minlen=0):
    if frm == to: return lpad(string,get_code_string(frm)[0],minlen)
    return encode(decode(string,frm),to,minlen)

### JSON access (for pybtctool convenience)

def access(obj,prop):
    if isinstance(obj,dict):
        if prop in obj: return obj[prop]
        elif '.' in prop: return obj[float(prop)]
        else: return obj[int(prop)]
    else:
        return obj[int(prop)]

def multiaccess(obj,prop):
    return [access(o,prop) for o in obj]

def slice(obj,start=0,end=2**200):
    return obj[int(start):int(end)]

def count(obj):
    return len(obj)

_sum = sum
def sum(obj):
    return _sum(obj)
    
### Elliptic Curve functions

def isinf(p): return p[0] == 0 and p[1] == 0

def base10_add(a,b):
  if isinf(a): return b[0],b[1]
  if isinf(b): return a[0],a[1]
  if a[0] == b[0]: 
    if a[1] == b[1]: return base10_double((a[0],a[1]))
    else: return (0,0)
  m = ((b[1]-a[1]) * inv(b[0]-a[0],P)) % P
  x = (m*m-a[0]-b[0]) % P
  y = (m*(a[0]-x)-a[1]) % P
  return (x,y)

def privkey_to_pubkey_bin(exponent, compressed=False):
    pubkey_buffer = ctypes.create_string_buffer(65)
    pubkey_length = ctypes.c_int()
    sipa.secp256k1_ec_pubkey_create(
        ctypes.byref(pubkey_buffer), 
        ctypes.byref(pubkey_length),
        exponent,
        int(compressed))
    return pubkey_buffer.raw

def base10_multiply(point, exponent):
    exponent = encode_privkey(exponent, 'bin')
    if point != G:
        pubkey = encode_pubkey(point, 'bin')
        pubkey_buffer = ctypes.create_string_buffer(len(pubkey))
        pubkey_length = ctypes.c_int()
        pubkey_buffer.value = pubkey
        pubkey_length.value = len(pubkey)
        sipa.secp256k1_ec_pubkey_tweak_mul(
            ctypes.byref(pubkey_buffer), 
            pubkey_length,
            exponent)
    else:
        pubkey_buffer = ctypes.create_string_buffer(65)
        pubkey_length = ctypes.c_int()
        sipa.secp256k1_ec_pubkey_create(
            ctypes.byref(pubkey_buffer), 
            ctypes.byref(pubkey_length),
            exponent,
            0)
    x = decode(pubkey_buffer.raw[1:33], 256)
    y = decode(pubkey_buffer.raw[33:65], 256)
    return (x, y)

# Functions for handling pubkey and privkey formats

def get_pubkey_format(pub):
    if isinstance(pub,(tuple,list)): return 'decimal'
    elif len(pub) == 65 and pub[0] == '\x04': return 'bin'
    elif len(pub) == 130 and pub[0:2] == '04': return 'hex'
    elif len(pub) == 33 and pub[0] in ['\x02','\x03']: return 'bin_compressed'
    elif len(pub) == 66 and pub[0:2] in ['02','03']: return 'hex_compressed'
    elif len(pub) == 64: return 'bin_electrum'
    elif len(pub) == 128: return 'hex_electrum'
    else: raise Exception("Pubkey not in recognized format")

def encode_pubkey(pub,formt):
    if not isinstance(pub,(tuple,list)):
        pub = decode_pubkey(pub)
    if formt == 'decimal': return pub
    elif formt == 'bin': return '\x04' + encode(pub[0],256,32) + encode(pub[1],256,32)
    elif formt == 'bin_compressed': return chr(2+(pub[1]%2)) + encode(pub[0],256,32)
    elif formt == 'hex': return '04' + encode(pub[0],16,64) + encode(pub[1],16,64)
    elif formt == 'hex_compressed': return '0'+str(2+(pub[1]%2)) + encode(pub[0],16,64)
    elif formt == 'bin_electrum': return encode(pub[0],256,32) + encode(pub[1],256,32)
    elif formt == 'hex_electrum': return encode(pub[0],16,64) + encode(pub[1],16,64)
    else: raise Exception("Invalid format!")

def decode_pubkey(pub,formt=None):
    if not formt: formt = get_pubkey_format(pub)
    if formt == 'decimal': return pub
    elif formt == 'bin': return (decode(pub[1:33],256),decode(pub[33:65],256))
    elif formt == 'bin_compressed':
        x = decode(pub[1:33],256)
        beta = pow(x*x*x+A*x+B,(P+1)/4,P)
        y = (P-beta) if ((beta + ord(pub[0])) % 2) else beta
        return (x,y)
    elif formt == 'hex': return (decode(pub[2:66],16),decode(pub[66:130],16))
    elif formt == 'hex_compressed':
        return decode_pubkey(pub.decode('hex'),'bin_compressed')
    elif formt == 'bin_electrum':
        return (decode(pub[:32],256),decode(pub[32:64],256))
    elif formt == 'hex_electrum':
        return (decode(pub[:64],16),decode(pub[64:128],16))
    else: raise Exception("Invalid format!")

def get_privkey_format(priv):
    if isinstance(priv,(int,long)): return 'decimal'
    elif len(priv) == 32: return 'bin'
    elif len(priv) == 33: return 'bin_compressed'
    elif len(priv) == 64: return 'hex'
    elif len(priv) == 66: return 'hex_compressed'
    else:
        bin_p = b58check_to_bin(priv)
        if len(bin_p) == 32: return 'wif'
        elif len(bin_p) == 33: return 'wif_compressed'
        else: raise Exception("WIF does not represent privkey")

def encode_privkey(priv,formt,vbyte=0):
    if not isinstance(priv,(int,long)):
        return encode_privkey(decode_privkey(priv),formt,vbyte)
    if formt == 'decimal': return priv
    elif formt == 'bin': return encode(priv,256,32)
    elif formt == 'bin_compressed': return encode(priv,256,32)+'\x01'
    elif formt == 'hex': return encode(priv,16,64)
    elif formt == 'hex_compressed': return encode(priv,16,64)+'01'
    elif formt == 'wif':
        return bin_to_b58check(encode(priv,256,32),128+int(vbyte))
    elif formt == 'wif_compressed':
        return bin_to_b58check(encode(priv,256,32)+'\x01',128+int(vbyte))
    else: raise Exception("Invalid format!")

def decode_privkey(priv,formt=None):
    if not formt: formt = get_privkey_format(priv)
    if formt == 'decimal': return priv
    elif formt == 'bin': return decode(priv,256)
    elif formt == 'bin_compressed': return decode(priv[:32],256)
    elif formt == 'hex': return decode(priv,16)
    elif formt == 'hex_compressed': return decode(priv[:64],16)
    else:
        bin_p = b58check_to_bin(priv)
        if len(bin_p) == 32: return decode(bin_p,256)
        elif len(bin_p) == 33: return decode(bin_p[:32],256)
        else: raise Exception("WIF does not represent privkey")

def add_pubkeys(p1,p2):
  f1,f2 = get_pubkey_format(p1), get_pubkey_format(p2)
  return encode_pubkey(base10_add(decode_pubkey(p1,f1),decode_pubkey(p2,f2)),f1)

def add_privkeys(p1,p2):
  f1,f2 = get_privkey_format(p1), get_privkey_format(p2)
  return encode_privkey((decode_privkey(p1,f1) + decode_privkey(p2,f2)) % N,f1)

def multiply(pubkey,privkey):
  f1,f2 = get_pubkey_format(pubkey), get_privkey_format(privkey)
  pubkey, privkey = decode_pubkey(pubkey,f1), decode_privkey(privkey,f2)
  # http://safecurves.cr.yp.to/twist.html
  if not isinf(pubkey) and (pubkey[0]**3+B-pubkey[1]*pubkey[1]) % P != 0: 
      raise Exception("Point not on curve")
  return encode_pubkey(base10_multiply(pubkey,privkey),f1)

def divide(pubkey,privkey):
    factor = inv(decode_privkey(privkey),N)
    return multiply(pubkey,factor)

def compress(pubkey):
    f = get_pubkey_format(pubkey)
    if 'compressed' in f: return pubkey
    elif f == 'bin': return encode_pubkey(decode_pubkey(pubkey,f),'bin_compressed')
    elif f == 'hex' or f == 'decimal':
        return encode_pubkey(decode_pubkey(pubkey,f),'hex_compressed')

def decompress(pubkey):
    f = get_pubkey_format(pubkey)
    if 'compressed' not in f: return pubkey
    elif f == 'bin_compressed': return encode_pubkey(decode_pubkey(pubkey,f),'bin')
    elif f == 'hex_compressed' or f == 'decimal':
        return encode_pubkey(decode_pubkey(pubkey,f),'hex')

def privkey_to_pubkey(privkey):
    f = get_privkey_format(privkey)
    privkey = decode_privkey(privkey,f)
    if privkey == 0 or privkey >= N:
        raise Exception("Invalid privkey")
    if f in ['bin','bin_compressed','hex','hex_compressed','decimal']:
        return encode_pubkey(base10_multiply(G,privkey),f)
    else:
        return encode_pubkey(base10_multiply(G,privkey),f.replace('wif','hex'))

privtopub = privkey_to_pubkey

def privkey_to_address(priv,magicbyte=0):
    return pubkey_to_address(privkey_to_pubkey(priv),magicbyte)
privtoaddr = privkey_to_address

def neg_pubkey(pubkey): 
    f = get_pubkey_format(pubkey)
    pubkey = decode_pubkey(pubkey,f)
    return encode_pubkey((pubkey[0],(P-pubkey[1]) % P),f)

def neg_privkey(privkey):
    f = get_privkey_format(privkey)
    privkey = decode_privkey(privkey,f)
    return encode_privkey((N - privkey) % N,f)

def subtract_pubkeys(p1, p2):
  f1,f2 = get_pubkey_format(p1), get_pubkey_format(p2)
  k2 = decode_pubkey(p2,f2)
  return encode_pubkey(base10_add(decode_pubkey(p1,f1),(k2[0],(P - k2[1]) % P)),f1)

def subtract_privkeys(p1, p2):
  f1,f2 = get_privkey_format(p1), get_privkey_format(p2)
  k2 = decode_privkey(p2,f2)
  return encode_privkey((decode_privkey(p1,f1) - k2) % N,f1)

### Hashes

def bin_hash160(string):
   intermed = hashlib.sha256(string).digest()
   digest = ''
   try:
       digest = hashlib.new('ripemd160',intermed).digest()
   except:
       digest = ripemd.RIPEMD160(intermed).digest()
   return digest
def hash160(string):
    return bin_hash160(string).encode('hex')

def bin_sha256(string):
    return hashlib.sha256(string).digest()
def sha256(string):
    return bin_sha256(string).encode('hex')

def bin_dbl_sha256(string):
   return hashlib.sha256(hashlib.sha256(string).digest()).digest()
def dbl_sha256(string):
   return bin_dbl_sha256(string).encode('hex')

def bin_slowsha(string):
    orig_input = string
    for i in range(100000):
        string = hashlib.sha256(string + orig_input).digest()
    return string
def slowsha(string):
    return bin_slowsha(string).encode('hex')

def hash_to_int(x):
    if len(x) in [40,64]: return decode(x,16)
    else: return decode(x,256)

def num_to_var_int(x):
    x = int(x)
    if x < 253: return chr(x)
    elif x < 65536: return chr(253) + encode(x,256,2)[::-1]
    elif x < 4294967296: return chr(254) + encode(x,256,4)[::-1]
    else: return chr(255) + encode(x,256,8)[::-1]

# WTF, Electrum?
def electrum_sig_hash(message):
    padded = "\x18Bitcoin Signed Message:\n" + num_to_var_int( len(message) ) + message
    return bin_dbl_sha256(padded)

def random_key():
    # Gotta be secure after that java.SecureRandom fiasco...
    entropy = os.urandom(32)+str(random.randrange(2**256))+str(int(time.time())**7)
    return sha256(entropy)

def random_electrum_seed():
    entropy = os.urandom(32)+str(random.randrange(2**256))+str(int(time.time())**7)
    return sha256(entropy)[:32]

### Encodings

def bin_to_b58check(inp,magicbyte=0):
    inp_fmtd = chr(int(magicbyte)) + inp
    leadingzbytes = len(re.match('^\x00*',inp_fmtd).group(0))
    checksum = bin_dbl_sha256(inp_fmtd)[:4]
    return '1' * leadingzbytes + changebase(inp_fmtd+checksum,256,58)

def b58check_to_bin(inp):
    leadingzbytes = len(re.match('^1*',inp).group(0))
    data = '\x00' * leadingzbytes + changebase(inp,58,256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return data[1:-4]

def get_version_byte(inp):
    leadingzbytes = len(re.match('^1*',inp).group(0))
    data = '\x00' * leadingzbytes + changebase(inp,58,256)
    assert bin_dbl_sha256(data[:-4])[:4] == data[-4:]
    return ord(data[0])

def hex_to_b58check(inp,magicbyte=0):
    return bin_to_b58check(inp.decode('hex'),magicbyte)

def b58check_to_hex(inp): return b58check_to_bin(inp).encode('hex')

def pubkey_to_address(pubkey,magicbyte=0):
   if isinstance(pubkey,(list,tuple)):
       pubkey = encode_pubkey(pubkey,'bin')
   if len(pubkey) in [66,130]:
       return bin_to_b58check(bin_hash160(pubkey.decode('hex')),magicbyte)
   return bin_to_b58check(bin_hash160(pubkey),magicbyte)

pubtoaddr = pubkey_to_address

### EDCSA

def der_encode_num(n):
    h = encode(n,256).encode('hex')
    b = binascii.unhexlify(h)
    if ord(b[0]) < 0x80:
        return h
    else:
        return '00' + h

def der_encode_sig(v,r,s):
    b1, b2 = der_encode_num(r), der_encode_num(s)
    left = '02'+encode(len(b1)/2,16,2)+b1
    right = '02'+encode(len(b2)/2,16,2)+b2
    return '30'+encode(len(left+right)/2,16,2)+left+right

def der_decode_sig(sig):
    leftlen = decode(sig[6:8],16)*2
    left = sig[8:8+leftlen]
    rightlen = decode(sig[10+leftlen:12+leftlen],16)*2
    right = sig[12+leftlen:12+leftlen+rightlen]
    return (None,decode(left,16),decode(right,16))

def encode_sig(v,r,s):
    vb, rb, sb = chr(v), encode(r,256), encode(s,256)
    return base64.b64encode(vb+'\x00'*(32-len(rb))+rb+'\x00'*(32-len(sb))+sb)

def decode_sig(sig):
    bytez = base64.b64decode(sig)
    return ord(bytez[0]), decode(bytez[1:33],256), decode(bytez[33:],256)

def ecdsa_raw_sign(msghash, priv):
    
    assert len(msghash) == 32
    msghash_buffer = ctypes.create_string_buffer(32)
    msghash_buffer.value = msghash
    sig_buffer = ctypes.create_string_buffer(64)
    seckey_buffer = ctypes.create_string_buffer(32)
    seckey_buffer.value = encode_privkey(priv, 'bin')
    recid = ctypes.c_int()
    
    result = sipa.secp256k1_ecdsa_sign_compact(
        msghash_buffer, ctypes.byref(sig_buffer), seckey_buffer, 0, 0, ctypes.byref(recid))
        
    if not result:
        raise Exception('ecdsa_raw_sign: invalid nonce')
    
    compressed = (4 if 'compressed' in get_privkey_format(priv) else 0)
    
    return 27 + compressed + recid.value, decode(sig_buffer.raw[:32], 256), decode(sig_buffer.raw[32:], 256)

def ecdsa_sign(msg,priv):
    msghash = electrum_sig_hash(msg)
    return encode_sig(*ecdsa_raw_sign(msghash,priv))

def ecdsa_raw_verify(msghash, sig, pub):
    
    sig_bin = der_encode_sig(*sig).decode('hex')
    pub_bin = encode_pubkey(pub, 'bin')
    
    msg_buffer = ctypes.create_string_buffer(len(msghash))
    msg_buffer.value = msghash
    sig_buffer = ctypes.create_string_buffer(len(sig_bin))
    sig_buffer.value = sig_bin
    sig_length = ctypes.c_int()
    sig_length.value = len(sig_bin)
    pub_buffer = ctypes.create_string_buffer(len(pub_bin))
    pub_buffer.value = pub_bin
    pub_length = ctypes.c_int()
    pub_length.value = len(pub_bin)
    
    return 1 == sipa.secp256k1_ecdsa_verify(
        msg_buffer, 
        sig_buffer, sig_length, 
        pub_buffer, pub_length)

def ecdsa_verify(msg,sig,pub):
    return ecdsa_raw_verify(electrum_sig_hash(msg),decode_sig(sig),pub)

def decode_recid_compressed(signature):
    v, r, s = decode_sig(signature)
    
    if v < 27 or v >= 35:
        raise Exception("Bad encoding")
    if v >= 31:
        compressed = True
        v -= 4
    else:
        compressed = False
    recid = v - 27
    return recid, compressed

def ecdsa_recover(message, signature):
    
    try:
        recid, compressed = decode_recid_compressed(signature)
    except:
        return None
    
    message = electrum_sig_hash(message)
    message_buffer = ctypes.create_string_buffer(len(message))
    message_buffer.value = message

    sig_buffer = ctypes.create_string_buffer(64)
    sig_buffer.value = signature.decode('base64')[1:]

    pubkey_buffer = ctypes.create_string_buffer(65)
    pubkey_length = ctypes.c_int()

    result = sipa.secp256k1_ecdsa_recover_compact(
        ctypes.byref(message_buffer),
        ctypes.byref(sig_buffer),
        ctypes.byref(pubkey_buffer), ctypes.byref(pubkey_length),
        int(compressed), recid)
    
    if result:
        return pubkey_buffer.raw[0:pubkey_length.value].encode('hex')