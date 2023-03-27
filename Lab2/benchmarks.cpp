#include "cryptlib.h"
#include "secblock.h"
#include "hrtimer.h"
#include "osrng.h"
#include "modes.h"
#include "aes.h"
#include "des.h"
#include <iostream>
using CryptoPP::CTR_Mode;

const double runTimeInSeconds = 3.0;
const double cpuFreq = 2.7 * 1000 * 1000 * 1000;

int main(int argc, char* argv[])
{
    using namespace CryptoPP;
    AutoSeededRandomPool prng;

    // AES encryption
    SecByteBlock aes_key(AES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(aes_key, aes_key.size());
    CTR_Mode< AES >::Encryption aes_cipher;
    aes_cipher.SetKeyWithIV(aes_key, aes_key.size(), aes_key);

    //// AES decryption
    //SecByteBlock aes_key(AES::DEFAULT_KEYLENGTH);
    //prng.GenerateBlock(aes_key, aes_key.size());
    //CTR_Mode< AES >::Decryption aes_cipher;
    //aes_cipher.SetKeyWithIV(aes_key, aes_key.size(), aes_key);

    // DES encryption
    SecByteBlock des_key(DES::DEFAULT_KEYLENGTH);
    prng.GenerateBlock(des_key, des_key.size());
    CTR_Mode< DES >::Encryption des_cipher;
    des_cipher.SetKeyWithIV(des_key, des_key.size(), des_key);

    //// DES decryption
    //SecByteBlock des_key(DES::DEFAULT_KEYLENGTH);
    //prng.GenerateBlock(des_key, des_key.size());
    //CTR_Mode< DES >::Decryption des_cipher;
    //des_cipher.SetKeyWithIV(des_key, des_key.size(), des_key);


    const int BUF_SIZE = RoundUpToMultipleOf(2048U,
        dynamic_cast<StreamTransformation&>(aes_cipher).OptimalBlockSize());

    AlignedSecByteBlock buf(BUF_SIZE);
    prng.GenerateBlock(buf, buf.size());

    double elapsedTimeInSeconds;
    unsigned long i = 0, blocks = 1;

    ThreadUserTimer timer;
    timer.StartTimer();
    
    std::cout << "AES benchmarks ... " << std::endl;
    do
    {
        blocks *= 2;
        for (; i<blocks; i++)
            aes_cipher.ProcessString(buf, BUF_SIZE);
        elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
    }
    while (elapsedTimeInSeconds < runTimeInSeconds);

    const double bytes = static_cast<double>(BUF_SIZE) * blocks;
    const double ghz = cpuFreq / 1000 / 1000 / 1000;
    const double mbs = bytes / elapsedTimeInSeconds / 1024 / 1024;
    const double cpb = elapsedTimeInSeconds * cpuFreq / bytes;

    std::cout << aes_cipher.AlgorithmName() << " benchmarks..." << std::endl;
    std::cout << "  " << ghz << " GHz cpu frequency"  << std::endl;
    std::cout << "  " << cpb << " cycles per byte (cpb)" << std::endl;
    std::cout << "  " << mbs << " MiB per second (MiB)" << std::endl;

    std::cout << "  " << elapsedTimeInSeconds << " seconds passed" << std::endl;
    std::cout << "  " << (word64) bytes << " bytes processed" << std::endl;

    i = 0; blocks = 1;
    timer.StartTimer();

    do
    {
        blocks *= 2;
        for (; i < blocks; i++)
            des_cipher.ProcessString(buf, BUF_SIZE);
        elapsedTimeInSeconds = timer.ElapsedTimeAsDouble();
    } while (elapsedTimeInSeconds < runTimeInSeconds);

    const double bytes1 = static_cast<double>(BUF_SIZE) * blocks;
    const double ghz1 = cpuFreq / 1000 / 1000 / 1000;
    const double mbs1 = bytes / elapsedTimeInSeconds / 1024 / 1024;
    const double cpb1 = elapsedTimeInSeconds * cpuFreq / bytes;

    std::cout << des_cipher.AlgorithmName() << " benchmarks..." << std::endl;
    std::cout << "  " << ghz1 << " GHz cpu frequency" << std::endl;
    std::cout << "  " << cpb1 << " cycles per byte (cpb)" << std::endl;
    std::cout << "  " << mbs1 << " MiB per second (MiB)" << std::endl;

    std::cout << "  " << elapsedTimeInSeconds << " seconds passed" << std::endl;
    std::cout << "  " << (word64)bytes1 << " bytes processed" << std::endl;

    if ((cpb < cpb1) && (mbs > mbs1))
        std::cout << "AES is faster";
    else
        std::cout << "DES is faster";

    return 0;
}