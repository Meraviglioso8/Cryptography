// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

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
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "aes.h"
using CryptoPP::AES;

#include "ccm.h"
using CryptoPP::CCM;

#include "assert.h"

#include <codecvt>
#include <io.h>
#include <fcntl.h>

#include <locale>
#include <string>

int main(int argc, char* argv[])
{
	AutoSeededRandomPool prng;

	byte key[ AES::DEFAULT_KEYLENGTH ];
    prng.GenerateBlock( key, sizeof(key) );

    // { 7, 8, 9, 10, 11, 12, 13 }
    byte iv[ 12 ];
    prng.GenerateBlock( iv, sizeof(iv) );    

    // { 4, 6, 8, 10, 12, 14, 16 }
    const int TAG_SIZE = 8;

	_setmode(_fileno(stdin), _O_U16TEXT); 
	std::cout<<"Input: ";
    std::wstring str ;
    std::getline(std::wcin, str);
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> convert;
    std::string plain = convert.to_bytes(str);
	string cipher, encoded, recovered;

	/*********************************\
	\*********************************/

	// Pretty print key
	encoded.clear();
	StringSource(key, sizeof(key), true,
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

		CCM< AES, TAG_SIZE >::Encryption e;
        e.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
        e.SpecifyDataLengths( 0, plain.size(), 0 );

        StringSource( plain, true,
            new AuthenticatedEncryptionFilter( e,
                new StringSink( cipher )
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)plain.data(), plain.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher.data(), cipher.size());
#endif
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
		CCM< AES, TAG_SIZE >::Decryption d;
        d.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
        d.SpecifyDataLengths( 0, cipher.size()-TAG_SIZE, 0 );

        AuthenticatedDecryptionFilter df( d,
            new StringSink( recovered )
        ); // AuthenticatedDecryptionFilter

        // The StringSource dtor will be called immediately
        //  after construction below. This will cause the
        //  destruction of objects it owns. To stop the
        //  behavior so we can get the decoding result from
        //  the DecryptionFilter, we must use a redirector
        //  or manually Put(...) into the filter without
        //  using a StringSource.
        StringSource( cipher, true,
            new Redirector( df /*, PASS_EVERYTHING */ )
        ); // StringSource
#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif

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
