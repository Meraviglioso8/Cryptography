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
#include "algebra.h"
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
    typedef PolynomialOver<ModularArithmetic<Integer>> PolyRing;
    PolyRing::Variable X;

    ModularArithmetic<Integer> modn(N);

    // Define the polynomials
    PolyRing::Element g1 = PowerMod((a*X + b), e, modn) - C1;
    PolyRing::Element g2 = PowerMod(X, e, modn) - C2;

    // Compute the GCD of g1 and g2
    PolyRing::Element gcd_poly = PolyRing::GCD(g1, g2).monic();

    // Extract the coefficients of the GCD polynomial
    std::vector<Integer> coeffs;
    for (int i = 0; i <= gcd_poly.Degree(); i++) {
        coeffs.push_back(gcd_poly.GetCoefficient(i));
    }

    // Compute the result as -a / lc
    Integer result = (-coeffs[0] * a_inv_b_mod_c(1, N)).Modulo(N);

    // Convert the result to a hexadecimal string and remove the trailing "L"
    std::string hexstr = Integer(result).ToString(16);
    if (hexstr.back() == 'L') {
        hexstr.pop_back();
    }

    // Convert the hexadecimal string to a plaintext string and return it
    std::string plaintext;
    HexDecoder decoder(new StringSink(plaintext));
    decoder.Put(reinterpret_cast<const byte*>(hexstr.data()), hexstr.size());
    decoder.MessageEnd();
    return plaintext;
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