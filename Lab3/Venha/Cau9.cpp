// Sample.cpp
//

//#include "stdafx.h"
#include "hrtimer.h"
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


const double runTimeInSeconds = 3.0;
const double cpuFreq = 2.7 * 1000 * 1000 * 1000;
int main(int argc, char* argv[])
{
    try
    {
        ////////////////////////////////////////////////
        // Generate keys
        AutoSeededRandomPool rng;

        InvertibleRSAFunction parameters;
        //913822829 if 100mb, how can i
        parameters.GenerateRandomWithKeySize( rng, 1024);

        RSA::PrivateKey privateKey( parameters );
        RSA::PublicKey publicKey( parameters );

        ////////////////////////////////////////////////
        // Secret to protect
        // static const int SECRET_SIZE = 16;
        //SecByteBlock plaintext( SECRET_SIZE );

        // Read the plaintext from a file
        std::ifstream plaintextFile("D:\plainText.txt");
        if (!plaintextFile)
        {
            std::cerr << "Fail" << std::endl;
            return 1;
        }

        std::string myPlaintext((std::istreambuf_iterator<char>(plaintextFile)),
            std::istreambuf_iterator<char>());


        int SECRET_SIZE = myPlaintext.length();
        SecByteBlock plaintext((const byte*)myPlaintext.data(), myPlaintext.size());;
        memcpy(plaintext, myPlaintext.c_str(), SECRET_SIZE);
        //memset( plaintext, 'A', SECRET_SIZE );

        ////////////////////////////////////////////////
        // Encrypt
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
        
        /***********************Show the cipher text***********************/
        
        // Convert cipher text to string
        string cipherText((const char*)ciphertext.data(), ciphertext.size());

        // Print cipher text to console
        cout << "Cipher text: " << cipherText << endl;

        ////////////////////////////////////////////////
        // DECRYPT
        RSAES_OAEP_SHA_Decryptor decryptor( privateKey );

        // Now that there is a concrete object, we can validate
        assert( 0 != decryptor.FixedCiphertextLength() );
        assert( ciphertext.size() <= decryptor.FixedCiphertextLength() );        

        // Create recovered text space
        size_t dpl = decryptor.MaxPlaintextLength( ciphertext.size() );
        assert( 0 != dpl );
        SecByteBlock recovered( dpl );

        // Paydirt
        DecodingResult result = decryptor.Decrypt( rng,
            ciphertext, ciphertext.size(), recovered );

        // More sanity checks
        assert( result.isValidCoding );        
        assert( result.messageLength <=
            decryptor.MaxPlaintextLength( ciphertext.size() ) );
        assert( plaintext.size() == result.messageLength );

        // At this point, we can set the size of the recovered
        //  data. Until decryption occurs (successfully), we
        //  only know its maximum size
        recovered.resize( result.messageLength );

        // SecByteBlock is overloaded for proper results below
        // Compare recovered to original
        string recoveredText((const char*)recovered.data(), recovered.size());
        cout << "Recovered plain text: " << recoveredText << endl;

        if (myPlaintext == recoveredText)
            cout << "Decryption succeeded" << endl;
        else
            cout << "Decryption failed" << endl;

        double elapsedTimeInSeconds;
        unsigned long i = 0, blocks = 1;

        CryptoPP::ThreadUserTimer timer;
        timer.StartTimer();


        //benchmark encryption
        try
        {
            do
            {
                blocks *= 2;
                for (; i < blocks; i++)
                    encryptor.Encrypt(rng, plaintext.data(), plaintext.size(), ciphertext.data());
                elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
            } while (elapsedTimeInSeconds < runTimeInSeconds);

            const double bytes = static_cast<double>(plaintext.size()) * blocks;
            const double ghz = cpuFreq / 1000 / 1000 / 1000;
            const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
            const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

            std::cout << encryptor.AlgorithmName() << " encrypt benchmarks..." << std::endl;
            std::cout << "  " << ghz << " GHz cpu frequency" << std::endl;
            std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
            std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
        }
        catch (CryptoPP::Exception& ex)
        {
            std::cerr << ex.what() << std::endl;
        }


        //benchmark decryption
        try
        {
            do
            {
                blocks *= 2;
                for (; i < blocks; i++)
                    decryptor.Decrypt(rng, ciphertext.data(), ciphertext.size(), plaintext.data());
                elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
            } while (elapsedTimeInSeconds < runTimeInSeconds);

            const double bytes = static_cast<double>(plaintext.size()) * blocks;
            const double ghz = cpuFreq / 1000 / 1000 / 1000;
            const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
            const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

            std::cout << decryptor.AlgorithmName() << " decrypt benchmarks..." << std::endl;
            std::cout << "  " << ghz << " GHz cpu frequency" << std::endl;
            std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
            std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
        }
        catch (CryptoPP::Exception& ex)
        {
            std::cerr << ex.what() << std::endl;
        }
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }
    std::cin.get();
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
