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

#include "aes.h"
using CryptoPP::AES;

#include "ccm.h"
using CryptoPP::CTR_Mode;

#include "assert.h"

#include <codecvt>
#include <io.h>
#include <fcntl.h>

#include <locale>
#include <string>

#include "files.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::FileSink;
using CryptoPP::FileSource;

using namespace std;
#include "hrtimer.h"
#include <cstdlib>
using std::exit;


//1MB
string InputFromFile(wstring wfilename)
{
    string plain, filename;
	wstring_convert<std::codecvt_utf8_utf16<wchar_t>> convert;
    filename = convert.to_bytes(wfilename);
    FileSource file(filename.data(), true, new StringSink(plain));
    return plain;
}

int main(int argc, char* argv[])
{
    double elapsedTimeInSeconds;
    unsigned long i = 0, blocks = 1;
    const double runTimeInSeconds = 3.0;
	const double cpuFreq = 2.8 * 1000 * 1000 * 1000;
    using namespace CryptoPP;
    AutoSeededRandomPool prng;

    wstring_convert<std::codecvt_utf8_utf16<wchar_t>> convert;

    SecByteBlock key(16);
    prng.GenerateBlock(key, key.size());

    const int BUF_SIZE = 8;


    SecByteBlock iv(AES::BLOCKSIZE);
    prng.GenerateBlock(iv, iv.size());


    //1MB input
    string plain;
	plain = InputFromFile(L"text.txt");

    SecByteBlock utf8Block(plain.size());
    std::memcpy(utf8Block, plain.c_str(), utf8Block.size());

    AlignedSecByteBlock buf(utf8Block.size());
    std::memcpy(buf, utf8Block, buf.size());

    // Encrypt the plaintext
    CTR_Mode< AES >::Encryption encryption;
    encryption.SetKeyWithIV(key, key.size(), iv);

    AlignedSecByteBlock ciphertext(buf.size());
    encryption.ProcessData(ciphertext, buf, buf.size());

    // Decrypt the ciphertext
    CTR_Mode< AES >::Decryption decryption;
    decryption.SetKeyWithIV(key, key.size(), iv);

    AlignedSecByteBlock recoveredtext(buf.size());
    decryption.ProcessData(recoveredtext, ciphertext, ciphertext.size());

    //std::wstring recoveredUtf16String = convert.from_bytes(std::string((const char*)recoveredtext.begin(), recoveredtext.size()));

    //std::cout << "Encrypted ciphertext: " << std::endl;
    //StringSource(ciphertext, ciphertext.size(), true, new HexEncoder(new FileSink(std::cout)));
    //std::cout << std::endl;
    //std::wcout << "Recovered plaintext: " << recoveredUtf16String << std::endl;




    ThreadUserTimer timer;
    timer.StartTimer();


    //benchmark encryption
    try 
    {
        do
        {
            blocks *= 2;
            for (; i < blocks; i++)
                encryption.ProcessData(buf, buf, buf.size());
            elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
        } while (elapsedTimeInSeconds < runTimeInSeconds);

        const double bytes = static_cast<double>(buf.size()) * blocks;
        const double ghz = cpuFreq / 1000 / 1000 / 1000;
        const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
        const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

        std::cout << encryption.AlgorithmName() << " encrypt benchmarks..." << std::endl;
        std::cout << "  " << ghz << " GHz cpu frequency" << std::endl;
        std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
        std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
    }
    catch(Exception)
    {
    }
    
    //benchmark encryption
    try 
    {
        do
        {
            blocks *= 2;
            for (; i < blocks; i++)
                decryption.ProcessData(buf, buf, buf.size());
            elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
        } while (elapsedTimeInSeconds < runTimeInSeconds);

        const double bytes = static_cast<double>(buf.size()) * blocks;
        const double ghz = cpuFreq / 1000 / 1000 / 1000;
        const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
        const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

        std::cout << decryption.AlgorithmName() << " decrypt benchmarks..." << std::endl;
        std::cout << "  " << ghz << " GHz cpu frequency" << std::endl;
        std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
        std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
    }
    catch(Exception)
    {
    }

    return 0;
}