//In gcm mode we have to use a 16 bytes bufFsize
/*
* The OptimalBlockSize function returns the block size required for authentication, which is 16 bytes for GCM mode. 
Since we are encrypting less than 16 bytes of data, we use a buffer size of 16 bytes.
*/
#include "cryptlib.h"
#include "secblock.h"
#include "hrtimer.h"
#include "osrng.h"
#include "gcm.h"
#include "aes.h"
#include <iostream>
using CryptoPP::GCM;
using CryptoPP::AES;

const double runTimeInSeconds = 3.0;
const double cpuFreq = 2.7 * 1000 * 1000 * 1000;

int main(int argc, char* argv[])
{
    using namespace CryptoPP;
    AutoSeededRandomPool prng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    const int BUF_SIZE = 16;

    AlignedSecByteBlock buf(BUF_SIZE);
    prng.GenerateBlock(buf, buf.size());
  
    double elapsedTimeInSeconds;
    unsigned long i = 0, blocks = 1;

    ThreadUserTimer timer;
    timer.StartTimer();

    try
    {
        GCM< AES >::Encryption encryption;
        encryption.SetKeyWithIV(key, key.size(), key + key.size(), key.size());

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
        GCM< AES >::Decryption decryption;
        decryption.SetKeyWithIV(key, key.size(), key + key.size(), key.size());
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
