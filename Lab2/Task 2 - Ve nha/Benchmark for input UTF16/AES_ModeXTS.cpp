﻿#include "cryptlib.h"
#include "secblock.h"
#include "hrtimer.h"
#include "osrng.h"
#include "xts.h"
#include "aes.h"
#include <iostream>
#include <string>
#include <locale>
#include <codecvt>
#include <hex.h>
#include <files.h>

using CryptoPP::XTS_Mode;
using CryptoPP::AES;

const double runTimeInSeconds = 3.0;
const double cpuFreq = 2.7 * 1000 * 1000 * 1000;

int main(int argc, char* argv[])
{
    std::setlocale(LC_ALL, "vi_VN.UTF-8");

    using namespace CryptoPP;
    AutoSeededRandomPool prng;

    SecByteBlock key(64);
    prng.GenerateBlock(key, key.size());


    std::cout << "Key: " << std::endl;
    StringSource(key, key.size(), true, new HexEncoder(new FileSink(std::cout)));
    std::cout << std::endl;


    XTS_Mode< AES >::Encryption encryption;
    encryption.SetKeyWithIV(key, key.size() / 2, key + key.size() / 2);

    // Generate a UTF-16 encoded string
    std::wstring_convert<std::codecvt_utf16<wchar_t>> converter;
    
    /*******************************************************************/
    /************************INPUT STRING HERE**************************/
    
    std::wstring utf16String = L"MMH khó quá huhu";
    SecByteBlock utf8Block(converter.to_bytes(utf16String).size());
    std::memcpy(utf8Block, converter.to_bytes(utf16String).c_str(), utf8Block.size());

    AlignedSecByteBlock buf(utf8Block.size());
    std::memcpy(buf, utf8Block, buf.size());

    // Encrypt the plaintext
    AlignedSecByteBlock ciphertext(buf.size());
    encryption.ProcessData(ciphertext, buf, buf.size());

    // Decrypt the ciphertext
    XTS_Mode< AES >::Decryption decryption;
    decryption.SetKeyWithIV(key, key.size() / 2, key + key.size() / 2);

    AlignedSecByteBlock recoveredtext(buf.size());
    decryption.ProcessData(recoveredtext, ciphertext, ciphertext.size());

    // Convert the recovered text from UTF-8 to UTF-16
    std::wstring recoveredUtf16String = converter.from_bytes(std::string((const char*)recoveredtext.begin(), recoveredtext.size()));

    std::cout << "Plain text: " << std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(utf16String) << std::endl;
    std::cout << "Ciphertext: " << std::endl;
    StringSource(ciphertext, ciphertext.size(), true, new HexEncoder(new FileSink(std::cout)));
    std::cout << std::endl;
    std::cout << "Recovered text: " << std::wstring_convert<std::codecvt_utf8<wchar_t>>().to_bytes(recoveredUtf16String) << std::endl;

    double elapsedTimeInSeconds;
    unsigned long i = 0, blocks = 1;

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
