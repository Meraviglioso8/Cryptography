/*Seem like XTS mode can't run with input < 64 bits = 8 bytes
So the buff_size cant be 8
I have to set the 64 bits key for it to run :(
*/
#include "cryptlib.h"
#include "secblock.h"
#include "hrtimer.h"
#include "osrng.h"
#include "modes.h"
#include "aes.h"
#include "xts.h"
#include <iostream>

using CryptoPP::XTS_Mode;
using CryptoPP::AES;

const double runTimeInSeconds = 3.0;
const double cpuFreq = 2.7 * 1000 * 1000 * 1000;

int main(int argc, char* argv[])
{
    using namespace CryptoPP;
    AutoSeededRandomPool prng;

    SecByteBlock key(64); // Use a 64-byte key for XTS mode
    prng.GenerateBlock(key, key.size());

    AlignedSecByteBlock buf(BUF_SIZE);
    prng.GenerateBlock(buf, buf.size());

    double elapsedTimeInSeconds;
    unsigned long i = 0, blocks = 1;

    ThreadUserTimer timer;
    timer.StartTimer();

    try
    {
        XTS_Mode< AES >::Encryption encryption;
        encryption.SetKeyWithIV(key, key.size() / 2, key + key.size() / 2);

        const int BUF_SIZE = RoundUpToMultipleOf(2048U,
            dynamic_cast<StreamTransformation&>(cipher).OptimalBlockSize());
        do
        {
            blocks *= 2;
            for (; i < blocks; i++)
                encryption.ProcessString(buf, BUF_SIZE);
            elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
        } while (elapsedTimeInSeconds < runTimeInSeconds);

        const double bytes = static_cast<double>(BUF_SIZE) * blocks;
        const double ghz = cpuFreq / 1000 / 1000 / 1000;
        const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
        const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

        std::cout << encryption.AlgorithmName() << " encryption benchmarks..." << std::endl;
        std::cout << "  " << ghz << " GHz cpu frequency" << std::endl;
        std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
        std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
    }
    catch (Exception) {

    }

    try
    {
        XTS_Mode< AES >::Decryption decryption;
        decryption.SetKeyWithIV(key, key.size() / 2, key + key.size() / 2);

        const int BUF_SIZE = RoundUpToMultipleOf(2048U,
            dynamic_cast<StreamTransformation&>(cipher).OptimalBlockSize());
        do
        {
            blocks *= 2;
            for (; i < blocks; i++)
                decryption.ProcessString(buf, BUF_SIZE);
            elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
        } while (elapsedTimeInSeconds < runTimeInSeconds);

        const double bytes = static_cast<double>(BUF_SIZE) * blocks;
        const double ghz = cpuFreq / 1000 / 1000 / 1000;
        const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
        const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

        std::cout << decryption.AlgorithmName() << " decryption benchmarks..." << std::endl;
        std::cout << "  " << ghz << " GHz cpu frequency" << std::endl;
        std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
        std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;
    }
    catch (Exception) {

    }

    return 0;
}
