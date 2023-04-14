// Sample.cpp
//

//#include "stdafx.h"

#include "rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "sha.h"
using CryptoPP::SHA1;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptlib.h"
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include <string>
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <assert.h>

using CryptoPP::byte;

#include <integer.h>
using CryptoPP::Integer;


int main(int argc, char* argv[])
{
    try
    {
        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        parameters.GenerateRandomWithKeySize(rng, 1024);

        //RSA::PrivateKey privateKey(parameters);
        //RSA::PublicKey publicKey(parameters);

        // Write keys to file
        /*
        {
            FileSink output("./privateKey.txt");
            privateKey.DEREncode(output);
        }
        {
            FileSink output("./publicKey.txt");
            publicKey.DEREncode(output);
        }
        */
        
        RSA::PrivateKey privateKey;
        RSA::PublicKey publicKey;
        {
            FileSource input("D:/Crypto_Code/Lab02/Github/Cryptography/Lab3/Trenlop/privateKey.txt",true);
            privateKey.BERDecode(input);
        }
        {
            FileSource input("D:/Crypto_Code/Lab02/Github/Cryptography/Lab3/Trenlop/publicKey.txt", true);
            publicKey.BERDecode(input);
        }

        ////////////////////////////////////////////////
        // Secret to protect
        // static const int SECRET_SIZE = 16;
        //SecByteBlock plaintext( SECRET_SIZE );

        // Input plaintext
        string myPlaintext = "RSA Encryption Schemes";

        //int SECRET_SIZE = myPlaintext.length();
        SecByteBlock plaintext((const byte*)myPlaintext.data(), myPlaintext.size());
        //memcpy(plaintext, myPlaintext.c_str(), SECRET_SIZE);
        //memset( plaintext, 'A', SECRET_SIZE );

        ////////////////////////////////////////////////
        // Encrypt
        /*
        RSAES_OAEP_SHA_Encryptor encryptor( publicKey );

        // Now that there is a concrete object, we can validate
        assert( 0 != encryptor.FixedMaxPlaintextLength() );
        assert( SECRET_SIZE <= encryptor.FixedMaxPlaintextLength() );        

        // Create cipher text space
        size_t ecl = encryptor.CiphertextLength( plaintext.size() );
        assert( 0 != ecl );
        SecByteBlock ciphertext( ecl );

        // Paydirt
        encryptor.Encrypt( rng, plaintext, plaintext.size(), ciphertext );
        */
        
        /***********************Show the cipher text***********************/
        /*
        // Convert cipher text to string
        string cipherText((const char*)ciphertext.data(), ciphertext.size());

        // Print cipher text to console
        std::cout << "Cipher text: " << cipherText << endl;

        std::ofstream encFile("./cipherText.txt");
        encFile << cipherText;
        */
        std::cout<<"Ciphertext read from file: "<<endl;
        std::string cipherText;
        std::ifstream readfile("D:/Crypto_Code/Lab02/Github/Cryptography/Lab3/Trenlop/cipherText.txt");//reading from the file
        if (readfile.is_open())
        {
            while (getline(readfile, cipherText))
            {
                std::cout <<cipherText << '\n';
          }
        }
        readfile.close();

        //SecByteBlock ciphertext((const byte*)cipherText.data(), cipherText.size());

        ////////////////////////////////////////////////
        // DECRYPT
        RSAES_OAEP_SHA_Decryptor decryptor( privateKey );

        // Now that there is a concrete object, we can validate
        assert( 0 != decryptor.FixedCiphertextLength() );
        assert( cipherText.size() <= decryptor.FixedCiphertextLength() );        

        // Create recovered text space
        size_t dpl = decryptor.MaxPlaintextLength( cipherText.size() );
        assert( 0 != dpl );
        SecByteBlock recovered( dpl );

        // Paydirt
        DecodingResult result = decryptor.Decrypt( rng,
            (const byte*)cipherText.data(), cipherText.size(), recovered );

        // More sanity checks
        assert( result.isValidCoding );        
        assert( result.messageLength <=
            decryptor.MaxPlaintextLength( cipherText.size() ) );
        assert( plaintext.size() == result.messageLength );

        // At this point, we can set the size of the recovered
        //  data. Until decryption occurs (successfully), we
        //  only know its maximum size
        recovered.resize( result.messageLength );

        // SecByteBlock is overloaded for proper results below
        // Compare recovered to original
        string recoveredText((const char*)recovered.data(), recovered.size());
        cout << "Recovered plain text: " << recoveredText << endl;
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }

	return 0;
}


void SaveKey( const RSA::PublicKey& PublicKey, const string& filename )
{
    // DER Encode Key - X.509 key format
    PublicKey.Save(
        FileSink( filename.c_str(), true /*binary*/ ).Ref()
    );
}

void SaveKey( const RSA::PrivateKey& PrivateKey, const string& filename )
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Save(
        FileSink( filename.c_str(), true /*binary*/ ).Ref()
    );
}

void LoadKey( const string& filename, RSA::PublicKey& PublicKey )
{
    // DER Encode Key - X.509 key format
    PublicKey.Load(
        FileSource( filename.c_str(), true, NULL, true /*binary*/ ).Ref()
    );
}

void LoadKey( const string& filename, RSA::PrivateKey& PrivateKey )
{
    // DER Encode Key - PKCS #8 key format
    PrivateKey.Load(
        FileSource( filename.c_str(), true, NULL, true /*binary*/ ).Ref()
    );
}
