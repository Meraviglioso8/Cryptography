 //g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;
#include <iostream>
using std::cout;
using std::cerr;

#include <locale>
#include <string>
using std::string;

#include "hrtimer.h"
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

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include <codecvt>
#include <io.h>
#include <fcntl.h>
using namespace std;

#include "files.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

//1MB
string InputFromFile(wstring wfilename)
{
    string plain, filename;
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> convert;
    filename = convert.to_bytes(wfilename);
    FileSource file(filename.data(), true, new StringSink(plain));
    return plain;
}


int main(int argc, char* argv[])
{ 
	ifstream file;
	//benchmark
	const int BUF_SIZE = 64;
	const double runTimeInSeconds = 3.0;
	const double cpuFreq = 2.7 * 1000 * 1000 * 1000;

    double elapsedTimeInSeconds;
    unsigned long i=0, blocks=1;

    CryptoPP::ThreadUserTimer timer;
    timer.StartTimer();
	AutoSeededRandomPool prng;

	SecByteBlock key(DES::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	CryptoPP::byte iv[DES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	CryptoPP::AlignedSecByteBlock buf(BUF_SIZE);
    prng.GenerateBlock(buf, buf.size());
	
	//manually input
     _setmode(_fileno(stdin), _O_U16TEXT); 
	std::cout<<"Input: ";
    std::wstring str ;
    std::getline(std::wcin, str);
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> convert;
    std::string strValue = convert.to_bytes(str);
    std::cout<<"plaintext: "<<strValue<<endl;
    
	//1MB input
	string strValue;
    // file.open("C:/Users/Admin/Desktop/text.txt");
	strValue = InputFromFile(L"text.txt");
    CryptoPP::byte byteArr[strValue.length()];
    // Iterate over characters in string,
    // convert them to byte and copy to byte array
    std::transform(
        strValue.begin(),
        strValue.end(),
        byteArr,
        [](const char& ch) {
            return CryptoPP::byte(ch);
        });
    // Iterate over byte array and print



	
	//string plain = "CBC Mode Test";
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
		//cout << "plain text: " << plain<< endl;

		CBC_Mode< DES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource(byteArr,sizeof(byteArr), true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource

	/*********************************\
	\*********************************/

		// Pretty print
	encoded.clear();
	StringSource(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	//cout << "cipher text: " << encoded << endl;
	/*********************************\
	\*********************************/
	//benchmark
		do
    {
        blocks *= 2;
        for (; i<blocks; i++)
            e.ProcessString(buf, BUF_SIZE);
        elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
    }
    while (elapsedTimeInSeconds < runTimeInSeconds);

    const double bytes = static_cast<double>(BUF_SIZE) * blocks;
    const double ghz = cpuFreq / 1000 / 1000 / 1000;
    const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
    const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

    std::cout << e.AlgorithmName() << " benchmarks for Encryption" << std::endl;
    std::cout << "  " << ghz << " GHz cpu frequency"  << std::endl;
    std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
    std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

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

	//cout << "recovered text: " << recovered << endl;
	/*********************************\
	\*********************************/
	//benchmark
		do
    {
        blocks *= 2;
        for (; i<blocks; i++)
            d.ProcessString(buf, BUF_SIZE);
        elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
    }
    while (elapsedTimeInSeconds < runTimeInSeconds);

    const double bytes = static_cast<double>(BUF_SIZE) * blocks;
    const double ghz = cpuFreq / 1000 / 1000 / 1000;
    const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
    const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

    std::cout << d.AlgorithmName() << " benchmarks for Decryption" << std::endl;
    std::cout << "  " << ghz << " GHz cpu frequency"  << std::endl;
    std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
    std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
	
	}
		
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

    // std::cout << "  " << elapsedTimeInSeconds << " seconds passed" << std::endl;
    // std::cout << "  " << (word64) bytes << " bytes processed" << std::endl;

    return 0;
}


