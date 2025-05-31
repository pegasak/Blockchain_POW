from gost_hash import hexdigest

p = int("EE8172AE8996608FB69359B89EB82A69854510E2977A4D63BC97322CE5DC3386"
        "EA0A12B343E9190F23177539845839786BB0C345D165976EF2195EC9B1C379E3", 16)
q = int("98915E7EC8265EDFCDA31E88F24809DDB064BDC7285DD50D7289F0AC6F49DD2D", 16)
a = int("9E96031500C8774A869582D4AFDE2127AFAD2538B4B6270A6F7C8837B50D50F2"
        "06755984A49E509304D648BE2AB5AAB18EBE2CD46AC3D8495B142AA6CE23E21C", 16)

def sign_message(message: bytes, x, k, a, p, q) -> (int, int):
    r = pow(a, k, p)
    r_bytes = r.to_bytes((p.bit_length() + 7) // 8, 'big')

    y = pow(a, x, p)
    y_bytes = y.to_bytes((p.bit_length() + 7) // 8, 'big')

    hash_input = y_bytes + r_bytes + message
    e = int.from_bytes(bytes.fromhex(hexdigest(256, hash_input)), 'big') % q
    s = (k + x * e) % q
    return e, s


def verify_signature(message: bytes, e, s, y, a, p, q) -> bool:
    # y^{-e} mod p = inverse(pow(y, e, p), p)
    y_e = pow(y, e, p)
    try:
        y_inv = pow(y_e, -1, p)
    except ValueError:
        return False

    r = (pow(a, s, p) * y_inv) % p

    byte_length = (p.bit_length() + 7) // 8
    r_bytes = r.to_bytes(byte_length, 'big')
    y_bytes = y.to_bytes(byte_length, 'big')

    hash_input = y_bytes + r_bytes + message
    e_prime = int.from_bytes(bytes.fromhex(hexdigest(256, hash_input)), 'big') % q

    return e == e_prime