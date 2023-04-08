#include "cryptlib.h"
#include "secblock.h"
#include "hrtimer.h"
#include "osrng.h"
#include "ccm.h"
#include "aes.h"
#include <iostream>
using CryptoPP::CCM;
using CryptoPP::AES;

const double runTimeInSeconds = 3.0;
const double cpuFreq = 2.7 * 1000 * 1000 * 1000;

int main(int argc, char* argv[])
{
    using namespace CryptoPP;
    AutoSeededRandomPool prng;

    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(key, key.size());

    const int BUF_SIZE = 8;

    AlignedSecByteBlock buf(BUF_SIZE);
    prng.GenerateBlock(buf, buf.size());

    double elapsedTimeInSeconds;
    unsigned long i = 0, blocks = 1;

    ThreadUserTimer timer;
    timer.StartTimer();
    try 
    {
        CCM< AES >::Encryption encryption;
        encryption.SetKeyWithIV(key, key.size(), key + key.size());
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
    catch (Exception)
    {
    }

    try 
    {
        CCM< AES >::Encryption decryption;
        decryption.SetKeyWithIV(key, key.size(), key + key.size());
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
    catch (Exception) 
    {

    }
    
    return 0;
}
