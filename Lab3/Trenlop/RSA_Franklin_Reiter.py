from sage.all import *
import random

def gcd(a, b): 
    while b:
        a, b = b, a % b
    return a.monic()

def generate_keypair(p, q):
    """Generate RSA key pair using two prime numbers p and q."""
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(1, phi)
    d = inverse_mod(e, phi)
    return ((n, e), (n, d))

def encrypt(plaintext, public_key):
    """Encrypt plaintext using RSA public key."""
    n, e = public_key
    ciphertext = pow(plaintext, e, n)
    return ciphertext

def franklinreiter(C1, C2, e, N, a, b):
    P = PolynomialRing(Zmod(N), 'x')
    p, q = factor(N)[0]
    while True:
        a_rand = Zmod(N)(randint(1, N-1))
        f = a_rand*P.gen() + b
        if a_rand.is_unit() and f.degree() == 1 and f.leading_coefficient().is_unit():
            break
    g1 = f**e - C1
    g2 = P.gen()**e - C2
    l = lcm(p-1, q-1)
    d = inverse_mod(e, l)
    print ("Result")
    result = -gcd(g1, g2).coefficients()[0]
    result_hex = format(int(result), 'x').replace("L","").rstrip()
    if len(result_hex) % 2 == 1:
        result_hex = '0' + result_hex
    return bytes.fromhex(result_hex)

def test_franklinreiter():
    
    e = 3
    
    a = 2
    b = 1

    p = 61
    q = 53
    N = p*q

    keypair = generate_keypair(p, q)
    public_key= keypair
    plaintext1 = b"matmahoc"
    plaintext2 = b"matmahic"
    C1 = encrypt(int.from_bytes(plaintext1, "big"), public_key)
    C2 = encrypt(int.from_bytes(plaintext2, "big"), public_key)
    
    Decrypted = franklinreiter(C1, C2, e, N, a, b)

test_franklinreiter()