#!/usr/bin/python
# Requires python-ecdsa and pycrypto

import ecdsa
import base64
import hashlib
import hmac
import urllib2
import struct
import argparse
import sys
import os
import textwrap
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import random

class SECP256k1:
    oid = (1, 3, 132, 0, 10)
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2FL
    order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141L
    a = 0x0000000000000000000000000000000000000000000000000000000000000000L
    b = 0x0000000000000000000000000000000000000000000000000000000000000007L
    h = 1
    Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798L
    Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8L
    curve = ecdsa.ellipticcurve.CurveFp(p, a, b)
    G = ecdsa.ellipticcurve.Point(curve, Gx, Gy, order)
    ecdsa_curve = ecdsa.curves.Curve("SECP256k1", curve, G, oid)

def encode_point(p, compressed):
    order = SECP256k1.order
    x_str = ecdsa.util.number_to_string(p.x(), order)
    if compressed:
        return chr(2 if (p.y() & 1) == 0 else 3) + x_str
    else:
        y_str = ecdsa.util.number_to_string(p.y(), order)
        return chr(4) + x_str + y_str

def decode_point(point):
    # See http://www.secg.org/download/aid-780/sec1-v2.pdf section 2.3.4
    curve = SECP256k1.curve
    order = SECP256k1.order
    baselen = ecdsa.util.orderlen(order)

    if point[0] == chr(4):
        # 3
        x_str = point[1:baselen + 1]
        y_str = point[baselen + 1:]
        return ecdsa.ellipticcurve.Point(curve, ecdsa.util.string_to_number(x_str), ecdsa.util.string_to_number(y_str), order)
    else:
        # 2.3
        if ord(point[0]) == 2:
            yp = 0
        elif ord(point[0]) == 3:
            yp = 1
        else:
            return None
        # 2.2
        x_str = point[1:baselen + 1]
        x = ecdsa.util.string_to_number(x_str)
        # 2.4.1
        alpha = ((x * x * x) + (curve.a() * x) + curve.b()) % curve.p()
        beta = ecdsa.numbertheory.square_root_mod_prime(alpha, curve.p())
        if (beta - yp) % 2 == 0:
            y = beta
        else:
            y = curve.p() - beta
        return ecdsa.ellipticcurve.Point(curve, x, y, order)

def double_sha256(data):
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()

class B58:
    chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    base = len(chars)

    def decode(self, v):
        bn = 0
        for c in v:
            index = self.chars.find(c)
            if index == -1: 
                break
            bn = bn * self.base 
            bn = bn + index

        leadingZeros = 0
        for c in v:
            if c == '1':
                leadingZeros = leadingZeros + 1
            else:
                break

        return (chr(0) * leadingZeros) + ecdsa.util.number_to_string(bn, bn)

    def encode(self, v):
        n = ecdsa.util.string_to_number(v)
        encoded = ""
        while n > 0:
            quotient, remainder = divmod(n, self.base)
            encoded = self.chars[remainder] + encoded
            n = quotient

        for c in v:
            if c == chr(0x00):
                encoded = '1' + encoded
            else:
                break
        return encoded

    def unwrap(self, v):
        msg = self.decode(v)
        if len(msg) < 4:
            return None
        payload = msg[:len(msg) - 4]
        h = double_sha256(payload)[0:4]
        if msg[len(msg) - 4:] != h:
            return None
        return payload

    def wrap(self, payload):
        h = double_sha256(payload)[0:4]
        return self.encode(payload + h)

def encode_varint(num):
    if num < 253L:
        return chr(num)
    elif num < 65536L:
        return chr(253) + struct.pack("<H", num)
    elif num < 4294967295L:
        return chr(254) + struct.pack("<I", num)
    else:
        return chr(255) + struct.pack("<Q", num)

def format_message_for_signing(message):
    header = "Bitcoin Signed Message:\n"
    return encode_varint(len(header)) + header + encode_varint(len(message)) + message

def private_key_to_secret_check_compressed(private_key):
    encoded = B58().unwrap(private_key)

    if len(encoded) < 1:
        return None, None

    if encoded[0] != chr(0x80):
        return None, None

    if len(encoded) == 33:
        return ecdsa.util.string_to_number(encoded[1:]), False
    elif len(encoded) == 34:
        if encoded[33] != chr(0x01):
            return None, None
        return ecdsa.util.string_to_number(encoded[1:33]), True

def private_key_to_secret(private_key):
    secret, compressed = private_key_to_secret_check_compressed(private_key)
    return secret

def secret_to_private_key(secret, compressed):
    encoded = chr(0x80) + ecdsa.util.number_to_string(secret, SECP256k1.order)
    if compressed:
        encoded = encoded + chr(0x01)
    return B58().wrap(encoded)

def generate_secret():
    return ecdsa.util.randrange(SECP256k1.order)

def public_key_to_address(public_key):
    addrtype = 0
    md = hashlib.new('ripemd160')
    md.update(hashlib.sha256(public_key).digest())
    return B58().wrap(chr(addrtype) + md.digest())

def address_to_public_key(address):
    mixed = urllib2.urlopen("https://blockchain.info/q/pubkeyaddr/" + address).read().decode("hex")
    if len(mixed) == 0:
        return None

    if mixed[0] == chr(4):
        return mixed[:65]
    else:
        return mixed[:33]

def private_key_to_public_key(private_key):
    secret, compressed = private_key_to_secret_check_compressed(private_key)
    return encode_point(SECP256k1.G * secret, compressed)

def signature_to_public_key(signature, message):
    # See http://www.secg.org/download/aid-780/sec1-v2.pdf section 4.1.6 primarily
    curve = SECP256k1.curve
    G = SECP256k1.G
    order = SECP256k1.order
    
    signature_bytes = base64.b64decode(signature)
    
    # The following is a variation of 4.1.6 Public Key Recovery Operation. Some weird magic is done to basically select j and k in the algorithm.
    # Essentially the first byte must be a number between 27 and 34. 27-30 are mapped to recid values 0-3 and 31-34 are mapped to the same values.
    # The only difference is that 27-30 means the public key that is hashed into the bitcoin address is uncompressed, and 31-34 means it's
    # compressed. For secp256k1, h (the cofactor) is 1, so the possible values of j in 4.1.6 is 0 and 1. k, of course can be 1 or 2. Even recid
    # means k = 1. Odd recid means k = 2. recids from 0-1 mean j = 0. recids from 2-3 mean j=1. All told, there's only four combinations of
    # j and k and four possible values for recid. Combined with two different states for the compression of the public key, that means there's
    # only 8 possible values for the first byte of the signature.

    meta = ord(signature_bytes[0])
    if meta < 27 or meta > 34:
        return None
    elif meta >= 31:
        compressed = True
        recid = meta - 31
    else:
        compressed = False
        recid = meta - 27

    j = recid // 2
    yp = 0 if (recid % 2) == 0 else 1

    ecdsa_signature = signature_bytes[1:]

    r, s = ecdsa.util.sigdecode_string(ecdsa_signature, order)
    
    # 1.1
    x = r + j * order

    # 1.3. This actually calculates for either effectively 02||X or 03||X depending on 'k' instead of always for 02||X as specified.
    # This substitutes for the lack of reversing R later on. -R actually is defined to be just flipping the y-coordinate in the elliptic curve.
    alpha = ((x * x * x) + (curve.a() * x) + curve.b()) % curve.p()
    beta = ecdsa.numbertheory.square_root_mod_prime(alpha, curve.p())
    if (beta - yp) % 2 == 0:
        y = beta
    else:
        y = curve.p() - beta

    # 1.4 Constructor of Point is supposed to check if nR is at infinity. 
    R = ecdsa.ellipticcurve.Point(curve, x, y, order)
    
    # 1.5 Compute e
    h = double_sha256(format_message_for_signing(message))
    e = ecdsa.util.string_to_number(h)

    # 1.6 Compute Q = r^-1(sR - eG)
    Q = ecdsa.numbertheory.inverse_mod(r, order) * (s * R + (-e % order) * G)

    # Not strictly necessary, but let's verify the message for paranoia's sake.
    if ecdsa.VerifyingKey.from_public_point(Q, curve=SECP256k1.ecdsa_curve).verify_digest(ecdsa_signature, h, sigdecode=ecdsa.util.sigdecode_string) != True:
        return None
    return encode_point(Q, compressed)

def verify(signature, message, address):
    public_key = signature_to_public_key(signature, message)
    if not public_key:
        return False

    if public_key_to_address(public_key) == address:
        return True
    else:
        return False

def sign(private_key, message):
    curve = SECP256k1.curve
    G = SECP256k1.G
    order = SECP256k1.order

    secret, compressed = private_key_to_secret_check_compressed(private_key)
    if secret == None:
        return None

    h = double_sha256(format_message_for_signing(message))
    signing_key = ecdsa.SigningKey.from_secret_exponent(secret, curve=SECP256k1.ecdsa_curve)
    ecdsa_signature = signing_key.sign_digest(h, sigencode=ecdsa.util.sigencode_string)
    
    public_point = signing_key.get_verifying_key().pubkey.point

    e = ecdsa.util.string_to_number(h)
    r, s = ecdsa.util.sigdecode_string(ecdsa_signature, order)

    # Okay, now we have to guess and check parameters for j and yp
    found = False
    for j in range(SECP256k1.h + 1):
        x = r + j * order
        alpha = ((x * x * x) + (curve.a() * x) + curve.b()) % curve.p()
        beta = ecdsa.numbertheory.square_root_mod_prime(alpha, curve.p())
        for yp in range(2):
            if (beta - yp) % 2 == 0:
                y = beta
            else:
                y = curve.p() - beta
            R = ecdsa.ellipticcurve.Point(curve, x, y, order)
            Q = ecdsa.numbertheory.inverse_mod(r, order) * (s * R + (-e % order) * G)
            if Q == public_point:
                found = True
                break
        if found:
            break

    recid = (2 * j) + yp
    if compressed:
        meta = chr(31 + recid)
    else:
        meta = chr(27 + recid)

    return base64.b64encode(meta + ecdsa_signature)

# PKCS#7 padding
def pad(message, block_size):
    padded = message
    last_block = len(message) % block_size
    to_pad = block_size - last_block
    for i in range(to_pad):
        padded = padded + chr(to_pad)
    return padded

def unpad(message, block_size):
    length = len(message)
    if length == 0:
        return message

    to_pad = ord(message[length - 1])
    if to_pad > block_size:
        return message

    if length < to_pad:
        return message

    pad_start = length - to_pad
    for c in message[pad_start:]:
        if c != chr(to_pad):
            return message

    return message[:pad_start]

# Format of the message is compressed SECP256k1 point R | HMAC-SHA-256 digest | 64-bit CTR prefix | PKCS#7 padded AES-256 encrypted data.
# HMAC and AES keys derived using a variation of ANSI-X9.63-KDF using SHA-256 instead of SHA-1. Encryption key (k_E) is
# SHA256(S | 32-bit big endian 1). HMAC key (k_M) is SHA256(S | 32-bit big endian 2). HMAC-SHA-256 is taken of both the 64-bit CTR prefix
# and the encrypted data.

# The key is the shared secret which is (r * public key) == ((r * curve base point) * private key), where r is a random number and (r * curve base point) is shared.
# This is because private key * curve base point == public key. It shouldn't be possible to get from r * curve base point back to r * public key without the private key.

def encrypt(public_key, message):
    padded = pad(message, AES.block_size)
    r = ecdsa.util.randrange(SECP256k1.order)
    R = SECP256k1.G * r
    S = (decode_point(public_key) * r).x()
    S_bytes = ecdsa.util.number_to_string(S, SECP256k1.order)
    k_E = hashlib.sha256(S_bytes + struct.pack(">I", 1)).digest()
    k_M = hashlib.sha256(S_bytes + struct.pack(">I", 2)).digest()
    prefix = random.getrandbits(64)
    prefix_bytes = struct.pack("<Q", prefix)
    ctr = Counter.new(64, prefix=prefix_bytes)
    cipher = AES.new(key=k_E, mode=AES.MODE_CTR, counter=ctr)
    c = cipher.encrypt(padded)
    d = hmac.new(k_M, prefix_bytes + c, hashlib.sha256).digest()
    return textwrap.fill(base64.b64encode(encode_point(R, True) + d + prefix_bytes + c), 200)

def decrypt(private_key, message):
    secret = private_key_to_secret(private_key)
    if secret == None:
        return None

    curve = SECP256k1.curve
    order = SECP256k1.order
    R_size = 1 + ecdsa.util.orderlen(order)
    mac_size = hashlib.sha256().digest_size

    message_binary = base64.b64decode(message)
    if len(message_binary) < (R_size + mac_size):
        return None

    R = decode_point(message_binary)
    d = message_binary[R_size:R_size + mac_size]
    prefix_bytes = message_binary[R_size + mac_size:R_size + mac_size + 8]
    c = message_binary[R_size + mac_size + 8:]
    S = (secret * R).x()
    S_bytes = ecdsa.util.number_to_string(S, SECP256k1.order)
    k_E = hashlib.sha256(S_bytes + struct.pack(">I", 1)).digest()
    k_M = hashlib.sha256(S_bytes + struct.pack(">I", 2)).digest()
    d_verify = hmac.new(k_M, prefix_bytes + c, hashlib.sha256).digest()
    if d_verify != d:
        return None
    ctr = Counter.new(64, prefix=prefix_bytes)
    cipher = AES.new(key=k_E, mode=AES.MODE_CTR, counter=ctr)
    padded = cipher.decrypt(c)
    return unpad(padded, AES.block_size)

def main():
    parser = argparse.ArgumentParser(description='Encrypt messages to bitcoin address holders using Elliptic Curve Integrated Encryption Scheme.')
    parser.add_argument('-e', '--encrypt', dest='mode', action='store_const', const='encrypt', help='Encrypt a string. Requires -a, -p or both -s and -m.')
    parser.add_argument('-a', '--with-address', dest='address', action='store', help='Try to look up the public key to encrypt with from a specified bitcoin address. This requires the blockchain.info API to return the correct public key and will disclose the address to them when we look it up. We verify the data from blockchain.info before trusting it. If specified along with -s and -m, no look-up is done, but we verify that the public key derived from the signed message is the one belonging to the bitcoin address specified. If specified along with -p, no look-up is done, but we verify that the public key provided is the one belonging to the bitcoin address specified.')
    parser.add_argument('-s', '--with-signature', dest='signature', action='store', help='Derive the public key to encrypt with from a message signed by the target bitcoin address. Requires -m as well.')
    parser.add_argument('-m', '--with-message', dest='message', action='store', help='Derive the public key to encrypt with from a message signed by the target bitcoin address. Requires -s as well.')
    parser.add_argument('-p', '--with-public-key', dest='public_key', action='store', help='Use the provided hex-encoded public key to encrypt with from a message signed by the target bitcoin address. If specified with both -s and -m, we verify that the public key derived from the signed message is the same one provided.')
    parser.add_argument('-d', '--decrypt', dest='mode', action='store_const', const='decrypt', help='Decrypt a string. Provide private key in Wallet Import Format (obtained with the dumpprivkey console command in the bitcoin client) in standard input, or first line of standard input if encrypted text is also provided on standard input. DO NOT PUT YOUR PRIVATE KEY ON THE COMMAND LINE.')
    parser.add_argument('--get-address', dest='mode', action='store_const', const='get_address', help='Convert a private key to a bitcoin address. Provide private key in Wallet Import Format in standard input. DO NOT PUT YOUR PRIVATE KEY ON THE COMMAND LINE.')
    parser.add_argument('--get-public-key', dest='mode', action='store_const', const='get_public_key', help='Convert a private key to a public key. Provide private key in Wallet Import Format in standard input. DO NOT PUT YOUR PRIVATE KEY ON THE COMMAND LINE.')
    parser.add_argument('--generate-private-key', dest='mode', action='store_const', const='generate_private_key', help='Generate a random private key in Wallet Import Format.')
    parser.add_argument('-v', '--verify', dest='mode', action='store_const', const='verify', help='Verify a message. Requires both -a and -s. Provide message in arguments or in standard input.')
    parser.add_argument('-i', '--sign', dest='mode', action='store_const', const='sign', help='Sign a message. Provide private key in Wallet Import Format in standard input. DO NOT PUT YOUR PRIVATE KEY ON THE COMMAND LINE.')
    parser.add_argument('text', nargs='?', action='store', help='String to encrypt, decrypt, sign or verify. If not specified, standard input will be used.')

    args = parser.parse_args()

    if args.mode != 'encrypt' and args.mode != 'decrypt' and args.mode != 'get_address' and args.mode != 'get_public_key' and args.mode != 'generate_private_key' and args.mode != 'sign' and args.mode != 'verify':
        parser.print_help()
        return

    if args.mode == 'encrypt' and not args.address and not (args.signature and args.message) and not args.public_key:
        sys.stderr.write("You must specify a bitcoin address (-a), a public key (-p), or a message signed by a bitcoin address (-m, -s)!\n")
        return

    if args.mode == 'encrypt':
        if args.public_key:
            public_key = args.public_key.decode('hex')
            if args.signature and args.message:
                if signature_to_public_key(args.signature, args.message) != public_key:
                    sys.stderr.write("Public key derived from provided signature does not match provided public key!\n")
                    return

            if args.address:
                if args.address != public_key_to_address(public_key):
                    sys.stderr.write("Public key does not match provided bitcoin address!\n")
                    return
        elif args.signature and args.message:
            public_key = signature_to_public_key(args.signature, args.message)
            if not public_key:
                sys.stderr.write("Could not derive public key from provided signature!\n")
                return

            if args.address:
                if args.address != public_key_to_address(public_key):
                    sys.stderr.write("Public key derived from provided signature does not match provided bitcoin address!\n")
                    return
        elif args.address:
            public_key = address_to_public_key(args.address)
            if not public_key:
                sys.stderr.write("Could not look up public key from provided bitcoin address! This can happen if this address has not yet SPENT any coins. Please ask the owner of the address to provide any signed message and use the -m and -s options.\n")
                return
            if public_key_to_address(public_key) != args.address:
                sys.stderr.write("Blockchain.info did not return the correct public key corresponding to the provided bitcoin address!\n")
                return

        if args.text:
            print encrypt(public_key, args.text)
            return
        else:
            print encrypt(public_key, sys.stdin.read())
    elif args.mode == 'decrypt':
        if args.text:
            private_key = sys.stdin.read()
            text = args.text
        else:
            private_key = sys.stdin.readline()
            text = sys.stdin.read()

        print decrypt(private_key, text)
    elif args.mode == 'get_address':
        private_key = sys.stdin.read()
        print public_key_to_address(private_key_to_public_key(private_key))
    elif args.mode == 'get_public_key':
        private_key = sys.stdin.read()
        print private_key_to_public_key(private_key).encode('hex')
    elif args.mode == 'generate_private_key':
        print secret_to_private_key(generate_secret(), True)
    elif args.mode == 'verify':
        if not args.address:
            sys.stderr.write("You must provide a address to verify with -a!\n")
            return

        if not args.signature:
            sys.stderr.write("You must provide a signature to verify with -s!\n")
            return

        if args.message:
            message = args.message 
        elif args.text:
            message = args.text
        else:
            message = sys.stdin.read()

        if verify(args.signature, message, args.address):
            print "Verified!"
        else:
            print "VERIFICATION FAILED."
    elif args.mode == 'sign':
        if args.text:
            private_key = sys.stdin.read()
            text = args.text
        else:
            private_key = sys.stdin.readline()
            text = sys.stdin.read()
        print sign(private_key, text)

if __name__ == "__main__":
    main()
