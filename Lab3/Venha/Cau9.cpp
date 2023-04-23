// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
#include <ostream>
#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;
using CryptoPP::byte;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "cryptlib.h"
using CryptoPP::Exception;

#include "hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::PK_EncryptorFilter;

#include "aes.h"
using CryptoPP::AES;

#include "ccm.h"
using CryptoPP::CBC_Mode;

#include "assert.h"

#include <codecvt>
#include <io.h>
#include <fcntl.h>

#include <locale>
#include <string>

#include "rsa.h"
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include "files.h"
#include "hrtimer.h"

const double runTimeInSeconds = 3.0;
const double cpuFreq = 2.7 * 1000 * 1000 * 1000;


int main(int argc, char* argv[])
{
	AutoSeededRandomPool prng;

	// Generate a random AES key and IV
	byte aes_key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(aes_key, sizeof(aes_key));

	byte aes_iv[AES::BLOCKSIZE];
	prng.GenerateBlock(aes_iv, sizeof(aes_iv));

	// Encrypt plaintext using AES-CBC
	//string plaintext = "Hello, world!";

	//input plaintext from file
	std::ifstream plaintextFile("D:/plainText.txt");
	if (!plaintextFile)
	{
		std::cerr << "Failed to open plaintext file" << std::endl;
		return 1;
	}

	std::string plaintext((std::istreambuf_iterator<char>(plaintextFile)), std::istreambuf_iterator<char>());

	string ciphertext;
	CBC_Mode< AES >::Encryption aes_encryptor;
	aes_encryptor.SetKeyWithIV(aes_key, sizeof(aes_key), aes_iv);
	StringSource(plaintext, true,
		new StreamTransformationFilter(aes_encryptor,
			new StringSink(ciphertext)
		)
	);

	// Open file for writing
	std::ofstream cipherFile("D:/cipherText.txt");
	if (!cipherFile)
	{
		std::cerr << "Failed to open ciphertext file" << std::endl;
		return 1;
	}
	cipherFile << ciphertext;
	cipherFile.close();



	// Generate an RSA key pair
	AutoSeededRandomPool rng;
	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, 2048);
	RSA::PrivateKey rsa_private_key(params);
	RSA::PublicKey rsa_public_key(params);

	//// Print the RSA key pair
	//cout << "RSA Private Key:" << endl;
	//string private_key_str;
	//StringSink private_key_sink(private_key_str);
	//rsa_private_key.DEREncode(private_key_sink);
	//cout << private_key_str << endl;

	//cout << "RSA Public Key:" << endl;
	//string public_key_str;
	//StringSink public_key_sink(public_key_str);
	//rsa_public_key.DEREncode(public_key_sink);
	//cout << public_key_str << endl;


	// Encrypt AES key and IV using RSA public key
	string aes_key_iv;
	aes_key_iv.append((const char*)aes_key, sizeof(aes_key));
	aes_key_iv.append((const char*)aes_iv, sizeof(aes_iv));



	string encrypted_key_iv;
	RSAES_OAEP_SHA_Encryptor encryptor(rsa_public_key);
	StringSource(aes_key_iv, true,
		new PK_EncryptorFilter(rng, encryptor,
			new StringSink(encrypted_key_iv)
		)
	);

	// Concatenate encrypted AES key/IV and ciphertext
	string encrypted_message;
	encrypted_message.append(encrypted_key_iv);
	encrypted_message.append(ciphertext);

	// Decrypt AES key and IV using RSA private key
	string decrypted_key_iv;
	RSAES_OAEP_SHA_Decryptor decryptor(rsa_private_key);
	StringSource(encrypted_key_iv, true,
		new PK_DecryptorFilter(rng, decryptor,
			new StringSink(decrypted_key_iv)
		)
	);

	// Get decrypted AES key and IV
	const char* aes_key_str = decrypted_key_iv.substr(0, AES::DEFAULT_KEYLENGTH).c_str();
	const char* aes_iv_str = decrypted_key_iv.substr(AES::DEFAULT_KEYLENGTH, AES::BLOCKSIZE).c_str();


	// Decrypt ciphertext using decrypted AES key and IV
	string decrypted_message;
	CBC_Mode< AES >::Decryption aes_decryptor;
	aes_decryptor.SetKeyWithIV((byte*)aes_key_str, AES::DEFAULT_KEYLENGTH, (byte*)aes_iv_str);
	StringSource(encrypted_message.substr(encrypted_key_iv.size()), true,
		new StreamTransformationFilter(aes_decryptor,
			new StringSink(decrypted_message)
		)
	);

	// Print decrypted message to file
	std::ofstream decrypted_file("D:/decrypted.txt");
	if (!decrypted_file)
	{
		std::cerr << "Failed to create decrypted file" << std::endl;
		return 1;
	}

	decrypted_file << decrypted_message;
	decrypted_file.close();

	std::cout << "Running hybrid RSA-AES ..." << std::endl;

	//Benchmark

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
				StringSource(aes_key_iv, true,
					new PK_EncryptorFilter(rng, encryptor,
						new StringSink(encrypted_key_iv)
					)
				);
			elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
		} while (elapsedTimeInSeconds < runTimeInSeconds);

		const double bytes = static_cast<double>(aes_key_iv.size()) * blocks;
		const double ghz = cpuFreq / 1000 / 1000 / 1000;
		const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
		const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

		std::cout << encryptor.AlgorithmName() << " key iv encrypt benchmarks..." << std::endl;
		std::cout << "  " << ghz << " GHz cpu frequency" << std::endl;
		std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
		std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
	}
	catch (CryptoPP::Exception& ex)
	{
		std::cerr << ex.what() << std::endl;
	}
	timer.StartTimer();

	//benchmark decryption
	try
	{
		do
		{
			blocks *= 2;
			for (; i < blocks; i++)
				aes_encryptor.SetKeyWithIV(aes_key, sizeof(aes_key), aes_iv);
			elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
		} while (elapsedTimeInSeconds < runTimeInSeconds);

		const double bytes = static_cast<double>(aes_key_iv.size()) * blocks;
		const double ghz = cpuFreq / 1000 / 1000 / 1000;
		const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
		const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

		std::cout << decryptor.AlgorithmName() << " key iv decrypt benchmarks..." << std::endl;
		std::cout << "  " << ghz << " GHz cpu frequency" << std::endl;
		std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
		std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
	}
	catch (CryptoPP::Exception& ex)
	{
		std::cerr << ex.what() << std::endl;
	}
	timer.StartTimer();

	//benchmark encryption
	try
	{
		do
		{
			blocks *= 2;
			for (; i < blocks; i++)
				aes_encryptor.SetKeyWithIV(aes_key, sizeof(aes_key), aes_iv);
				StringSource(plaintext, true,
					new StreamTransformationFilter(aes_encryptor,
						new StringSink(ciphertext)
					)
				);
			elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
		} while (elapsedTimeInSeconds < runTimeInSeconds);

		const double bytes = static_cast<double>(plaintext.size()) * blocks;
		const double ghz = cpuFreq / 1000 / 1000 / 1000;
		const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
		const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

		std::cout << aes_encryptor.AlgorithmName() << " plaintext encrypt benchmarks..." << std::endl;
		std::cout << "  " << ghz << " GHz cpu frequency" << std::endl;
		std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
		std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
	}
	catch (CryptoPP::Exception& ex)
	{
		std::cerr << ex.what() << std::endl;
	}

	timer.StartTimer();

	//benchmark decryption
	try
	{
		do
		{
			blocks *= 2;
			for (; i < blocks; i++)
				aes_decryptor.SetKeyWithIV((byte*)aes_key_str, AES::DEFAULT_KEYLENGTH, (byte*)aes_iv_str);
			elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
		} while (elapsedTimeInSeconds < runTimeInSeconds);

		const double bytes = static_cast<double>(plaintext.size()) * blocks;
		const double ghz = cpuFreq / 1000 / 1000 / 1000;
		const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
		const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

		std::cout << aes_decryptor.AlgorithmName() << " plaintext decrypt benchmarks..." << std::endl;
		std::cout << "  " << ghz << " GHz cpu frequency" << std::endl;
		std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
		std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
	}
	catch (CryptoPP::Exception& ex)
	{
		std::cerr << ex.what() << std::endl;
	}

	std::cin.get();
	

	return 0;
}

