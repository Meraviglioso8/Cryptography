#include "rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSASSA_PKCS1v15_SHA_Signer;
using CryptoPP::RSASSA_PKCS1v15_SHA_Verifier;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include "filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::SignatureVerificationFilter;
using CryptoPP::SignerFilter;

#include <string>
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include "files.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <filesystem>
#include <locale>
#include <codecvt>

#include "assert.h"
#include <io.h>

using namespace std;

int main(int argc, char* argv[])
{
    try
    {   
        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction params;
        params.GenerateRandomWithKeySize(rng, 3072);

        RSA::PrivateKey privateKey(params);
        RSA::PublicKey publicKey(params);

        string message="cuu toi mat ma hoc kho qua", recovered, signature;

        cout << "Message: " << message << endl;

        ////////////////////////////////////////////////
        // Sign and Encode
        RSASSA_PKCS1v15_SHA_Signer signer(privateKey);

        StringSource ss1(message, true, 
            new SignerFilter(rng, signer,
                new StringSink(signature)
        ) // SignerFilter
        ); // StringSource
        cout << "Signature : " << endl << signature << endl;

        //message="cuu toi mat ma hoc de qua";

        ////////////////////////////////////////////////
        // Verify and Recover
        RSASSA_PKCS1v15_SHA_Verifier verifier(publicKey);

        StringSource ss2(message+signature, true,
            new SignatureVerificationFilter(
                verifier, NULL,
                SignatureVerificationFilter::THROW_EXCEPTION
        ) // SignatureVerificationFilter
        ); // StringSource

        cout << "Verified signature on message" << endl;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }

	return 0;
}
