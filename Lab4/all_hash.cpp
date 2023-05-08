#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include "md5.h"
#include <iostream>
#include "hex.h"
#include "cryptlib.h"
using namespace CryptoPP;
using namespace std;

#include "files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;



Weak::MD5 hash;
std::string msg = "Yoda said, Do or do not. There is no try.";
std::string digest;

StringSource(msg, true, new HashFilter(hash, new StringSink(digest)));

std::cout << "Message: " << msg << std::endl;

std::cout << "Digest: ";
StringSource(digest, true, new Redirector(encoder));
std::cout << std::endl;