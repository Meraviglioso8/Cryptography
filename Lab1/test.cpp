// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;
#include <iostream>
using std::cout;
using std::cerr;
using std::endl;
#include <locale>
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

#include "des.h"
using CryptoPP::DES;

#include "modes.h"
using CryptoPP::CBC_Mode;
#include <string>
#include "secblock.h"
using CryptoPP::SecByteBlock;
#include <codecvt>
#include <io.h>
#include <fcntl.h>
using namespace std;

int main(int argc, char* argv[])
{
	AutoSeededRandomPool prng;

	SecByteBlock key(DES::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	CryptoPP::byte iv[DES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));
	
    //std::locale::global(std::locale("utf16"));
    //std::locale::global(std::locale(""));
    //_setmode(_fileno(stdin), _O_U16TEXT); 
    std::wstring str ;
    std::getline(std::wcin, str);
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> convert;
    std::string plain = convert.to_bytes(str);
    std::cout<<plain<<endl;
    string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

    // cout << "key length: " << DES::DEFAULT_KEYLENGTH << endl;
    // cout << "block size: " << DES::BLOCKSIZE << endl;

	// Pretty print key
	encoded.clear();
	StringSource(key, key.size(), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "key: " << encoded << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "iv: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		cout << "plain text: " << plain << endl;

		CBC_Mode< DES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;

	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode< DES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	return 0;
}

