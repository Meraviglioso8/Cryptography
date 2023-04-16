#include <iostream>
#include <string>
#include <vector>
#include "rsa.h"
#include "osrng.h"
#include "hex.h"
#include "files.h"
#include "filters.h"

#include "cryptlib.h"
#include "integer.h"
#include "polynomi.h"
#include "nbtheory.h"
#include "modarith.h"
using namespace CryptoPP;

Integer gcd(Integer& a, Integer& b) 
{
    Integer x = a;
    Integer y = b;
    Integer r = x % y;
    while (r != 0) {
        x = y;
        y = r;
        r = x % y;
    }
    return y;
}

std::string franklinreiter(const Integer& C1, const Integer& C2, const Integer& e, const Integer& N, const Integer& a, const Integer& b)
{
    // Define the polynomial ring
    typedef PolynomialOver<ModularArithmetic> Polynomial;
    ModularArithmetic modn(N);
    const RingOfPolynomialsOver<ModularArithmetic> P(modn, 1, "X");
    const Polynomial X(P, 1, 1); // X polynomial with coefficient type ModularArithmetic

    // Define the polynomials g1 and g2
    const Polynomial g1 = (a*X + b).ModExp(e, P) - Polynomial(C1, P);
    const Polynomial g2 = X.ModExp(e, P) - Polynomial(C2, P);

    // Compute the greatest common divisor of g1 and g2
    Polynomial r, q;
    Polynomial::Divide(r, q, g1, g2, P);
    const Integer result = -q.GetCoefficient(0).ToInt();

    // Convert the result to a hexadecimal string
    const std::string hex_result = result.ToHexString();
    return hex_result;
}

int main()
{
    AutoSeededRandomPool rng;

    // Generate a random 64-bit RSA key pair
    InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 256);

    // Extract the modulus
    Integer N = params.GetModulus();
    
    // Print the modulus
    std::cout << "n = " << std::hex << N << std::endl;

    Integer e("3");
    std::cout << "e = " << std::hex << e << std::endl;
    
    // Create the public key
    RSA::PublicKey publicKey;
    publicKey.Initialize(N, e);

    // Messages to be encrypted
    std::string message1 = "Hello world! Haha";
    std::string message2 = "Hello world! Hihi";

    // Convert the messages to Integers
    Integer m1((const byte*)message1.data(), message1.size());
    Integer m2((const byte*)message2.data(), message2.size());

    // Encrypt the messages
    Integer c1 = a_exp_b_mod_c(m1, e, N);
    Integer c2 = a_exp_b_mod_c(m2, e, N);

    // Convert the ciphertexts to strings in hexadecimal format
    std::string encoded1, encoded2;
    HexEncoder encoder1(new StringSink(encoded1));
    c1.Encode(encoder1, c1.ByteCount());
    encoder1.MessageEnd();

    HexEncoder encoder2(new StringSink(encoded2));
    c2.Encode(encoder2, c2.ByteCount());
    encoder2.MessageEnd();

    // Output the ciphertexts
    std::cout << "Message 1: " << message1 << std::endl;
    std::cout << "Message 2: " << message2 << std::endl;
    std::cout << "Ciphertext 1: " << encoded1 << std::endl;
    std::cout << "Ciphertext 2: " << encoded2 << std::endl;

    return 0;
}