#pragma once

#include <crypto++/config_int.h>
#include <crypto++/hmac.h>
#include <crypto++/misc.h>
#include <crypto++/pwdbased.h>
#include <crypto++/sha.h>

namespace btcpp::crypto {
using SHA256 = CryptoPP::SHA256;
using SHA512 = CryptoPP::SHA512;
using HMAC512 = CryptoPP::HMAC<CryptoPP::SHA512>;
using PBKDF2 = CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512>;
} // namespace btcpp::crypto
