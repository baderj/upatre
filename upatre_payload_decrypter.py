"""Upatre Payload Decrypter
Johannes Bader

Tries to decrypt the payload format of Upatre downloads

see
http://www.johannesbader.ch/2015/06/Win32-Upatre-BI-Part-4-Payload-Format/

"""
import os
import struct
import signal
import argparse
import libs.lznt1

def _p(field, value):
    if type(value) == int:
        value = value  & 0xFFFFFFFF
        print("{:15}: {:08x}".format(field, value))
    else:
        print("{:15}: {}".format(field, value))

def ror(value, places):
    return ((value >> places) ^ (value << (32 - places))) & 0xFFFFFFFF

def rol(value, places):
    return ((value << places) ^ (value >> (32 - places))) & 0xFFFFFFFF

def inc_dec_reverse(size_key, type_):
    u = (size_key & 0xFFFF)
    l = size_key >> 16
    if type_ == "inc":
        if l - 4 < 0:
            u -= 1
        l -= 4
    elif type_ == "dec":
        if l + 4 > 0xFFFF:
            u += 1
        l += 4
    elif type_ == "dec2":
        if l + 8 > 0xFFFF:
            u += 1
        l += 8
    return [((u << 16) ^ (l & 0xFFFF)) & 0xFFFFFFFF]

def rol_reverse(size_key):
    u = (size_key & 0xFFFF) << 16
    l = size_key >> 16
    lm = 0x0000FFFF
    um = 0xFFFF0000
    li = ror(l, 4) 
    lm = ror(lm, 4) 
    ui = ror(u, 3) 
    um = ror(um, 3) 
    k = (ui & um) ^ (li & lm)
    keys = [k, k + 0x00001000, k + 0x10000000, k + 0x10001000]
    return keys

def decrypt(c, key, ksa, check_key=None):
    p = c[0:4]
    for i in range(4,len(c), 4):
        if len(c[i:i+4]) == 4:
            enc = struct.unpack('I', c[i:i+4])[0]
            dec = enc ^ key
            p += struct.pack('I', dec)
            if ksa == "rol":
                key = rol(key, 1)
            elif ksa == "inc":
                key = (key + 1) & 0xFFFFFFFF 
            elif ksa == "dec":
                key = (key - 1) & 0xFFFFFFFF 
            elif ksa == "dec2":
                key = (key - 2) & 0xFFFFFFFF 
            elif ksa == "chk":
                key = (key + check_key) & 0xFFFFFFFF
            else:
                print("invalid ksa: {}".format(ksa))
                quit()
    return p

def handler(signum, frame):
    global timeout
    timeout = True
    raise Exception("timeout")

def decompress(p, old):
    if old:
        offset_data = 4
        compressed_size = len(p) - 4
    else:
        offset_data = struct.unpack('H', p[0xC:0xE])[0]
        compressed_size = struct.unpack('I', p[0xE:0x12])[0]
    unc = libs.lznt1.dCompressBuf(p[offset_data:offset_data + compressed_size])
    return unc

def offset_check(p):
    file_size = struct.unpack('I', p[0x12:0x16])[0]
    offset_stub = struct.unpack('H', p[0x8:0xA])[0]
    offset_data = struct.unpack('H', p[0xC:0xE])[0]
    compressed_size = struct.unpack('I', p[0xE:0x12])[0]
    if offset_stub > file_size or offset_data > file_size or \
            compressed_size > file_size:
        return 0
    else:
        return 1

def find_keys(c, enc_file): 
    size = os.stat(enc_file).st_size
    size_enc = struct.unpack('I', c[0x12:0x16])[0]
    size_key = struct.unpack('I', c[0x12:0x16])[0] ^ size
    keys = {}
    keys['inc'] = inc_dec_reverse(size_key, "inc")
    keys['dec'] = inc_dec_reverse(size_key, "dec")
    keys['dec2'] = inc_dec_reverse(size_key, "dec2")
    keys['rol'] = rol_reverse(size_key)
    return keys

def crack_payload(enc_file, key, check_key, ksa, old):
    with open(enc_file, 'rb') as r:
        c = r.read()

    if key and ksa:
        keys = {ksa: [key]}
    elif key:
        keys = {}
        for ksa in ['inc', 'dec', 'dec2', 'rol', 'chk']:
            keys[ksa] = [key]
    else:
        keys = find_keys(c, enc_file)

    print("testing potential keys".format(len(keys)))
    for ksa, tkeys in keys.items():
        for key in tkeys:
            _p("key (with ksa = {})".format(ksa), key)
            p = decrypt(c, key, ksa, check_key)
            s = 1 if old else offset_check(p)
            if not s:
                print(" -> invalid offsets")
                continue


            unc = decompress(p, old)
            try:
                unc = decompress(p, old)
            except Exception as e:
                print("  -> decompression failed {}".format(e))
                continue
            if unc[0:2] == "MZ": 
                print("  -> begins with MZ header, this is it!")
                out_file = "decrypted_" + enc_file
                with open(out_file, "wb") as w:
                    w.write(bytes(unc))
                print("  -> written decrypted exe to: {}".format(out_file))
                _p("  -> decrypt_key", key)
                _p("  -> ksa", ksa)
                _p("  -> check_key", struct.unpack("I", p[4:8])[0])
                _p("  -> stub entry", struct.unpack("H", p[8:0xA])[0])
                _p("  -> com. start", struct.unpack("H", p[0xC:0xE])[0])
                _p("  -> com. size", struct.unpack("I", p[0xE:0x12])[0])
                return 1 
            else:
                print("  -> file does not start with MZ header")
                continue

if __name__=="__main__":
    parser = argparse.ArgumentParser("decrypt Upatre payload")
    parser.add_argument("payload_file")
    parser.add_argument("-k", "--key", default="0")
    parser.add_argument("-s", "--ksa")
    parser.add_argument("-c", "--check_key", default="0")
    parser.add_argument("-o", "--old")
    args = parser.parse_args()
    crack_payload(args.payload_file, int(args.key, 16), int(args.check_key, 16),
            args.ksa, args.old)
