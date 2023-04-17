from sage.all import *

def franklinReiter(n,e,r,c1,c2):
    P = PolynomialRing(Zmod(n), "X")
    X = P.gen()
    f1 = X**e - c1
    f2 = (X + r)**e - c2
    # coefficient 0 = -m, which is what we wanted!
    return Integer(n-(compositeModulusGCD(f1,f2)).coefficients()[0])

  # GCD is not implemented for rings over composite modulus in Sage
  # so we do our own implementation. Its the exact same as standard GCD, but with
  # the polynomials monic representation
def compositeModulusGCD(a, b):
    if(b == 0):
        return a.monic()
    else:
        return compositeModulusGCD(b, a % b)

def testFranklinReiter():
    p = random_prime(2^512)
    q = random_prime(2^512)
    n = p * q # 1024-bit modulus
    e = 11

    m = randint(0, n) # some message we want to recover
    r = randint(0, n) # random padding

    c1 = pow(m + 0, e, n)
    c2 = pow(m + r, e, n)
    print("Message: ", m)
    recoveredM = franklinReiter(n,e,r,c1,c2)
    print("Recovered Message: ", recoveredM)
    assert recoveredM==m
    print("They are equal!")
    return True

testFranklinReiter()