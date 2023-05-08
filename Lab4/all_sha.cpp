#include <assert.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "md5.h"
#include<iostream>
using namespace CryptoPP;
using namespace std;
#include<string.h>
#include "filters.h"
#include "files.h"
#include "hex.h"

#include "sha.h"
void md5_func(string msg)
{
    HexEncoder encoder(new FileSink(std::cout));
    Weak::MD5 hash;
    std::string digest;
 

StringSource ( msg, true,
        new HashFilter(hash,new StringSink(digest)));
    std::cout<< "Message: " << msg << std::endl;

    std::cout<< "Digest: ";
StringSource(digest, true, new Redirector(encoder));
    std::cout<< endl;

    bool result;
StringSource (digest+msg, true, new HashVerificationFilter(hash,
                 new ArraySink((CryptoPP::byte*)&result, sizeof(result))));

    if (result == true)
        std::cout << "Verified hash over message" << std::endl;
    else
        std::cout << "Failed to verify hash over message" << std::endl;
}

void sha224_func(string msg)
{

HexEncoder encoder(new FileSink(std::cout));
std::string digest;
SHA224 hash;

StringSource(msg, true, new HashFilter(hash, new StringSink(digest)));

std::cout << "Message: " << msg << std::endl;

std::cout << "Digest: ";
StringSource(digest, true, new Redirector(encoder));
std::cout << std::endl;

bool result;
StringSource(digest+msg, true, new HashVerificationFilter(hash,
                 new ArraySink((CryptoPP::byte*)&result, sizeof(result))));

if (result == true)
    std::cout << "Verified hash over message" << std::endl;
else
    std::cout << "Failed to verify hash over message" << std::endl;

}
int main()
{
    string msg;
    int cs;
    cout<<"Input your message: ";
    getline(cin,msg);
    cout<<"Input the hash function you want"<<endl;
    cout<<"1. MD5"<<endl;
    cout<<"2. SHA224"<<endl;
    cout<<"3. SHA256"<<endl;
    cout<<"4. SHA384"<<endl;
    cout<<"5. SHA512"<<endl;
    cout<<"6. SHA3-224"<<endl;
    cout<<"7. SHA3-256"<<endl;
    cout<<"8. SHA3-384"<<endl;
    cout<<"9. SHA3-512"<<endl;
    cout<<"10. SHAKE128"<<endl;
    cout<<"11. SHAKE256"<<endl;
    cin>>cs;
    switch (cs)
    {
        case 1: 
        md5_func(msg);
        break;
        case 2:
        sha224_func(msg);
        break;


    }
}