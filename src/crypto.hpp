#pragma once

#include <crypto++/config_int.h>
#include <crypto++/hmac.h>
#include <crypto++/misc.h>
#include <crypto++/pwdbased.h>
#include <crypto++/ripemd.h>
#include <crypto++/sha.h>

#include <cstdlib>
#include <mutex>
#include <random>
#include <secp256k1.h>

namespace btcpp {
namespace crypto {
using SHA256 = CryptoPP::SHA256;
using SHA512 = CryptoPP::SHA512;
using HMAC512 = CryptoPP::HMAC<CryptoPP::SHA512>;
using PBKDF2 = CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512>;
struct HASH160 {
    static void CalculateDigest(uint8_t *digest, const uint8_t *input, size_t length);
    static constexpr size_t DIGESTSIZE = CryptoPP::RIPEMD160::DIGESTSIZE;
};
} // namespace crypto

namespace secp256k1 {
extern secp256k1_context *ctx;
extern std::once_flag init_flag;
// be sure to call this function every time you need the context
void init();

std::array<uint8_t, 33> getpublickey(const std::array<uint8_t, 32> &secret);
} // namespace secp256k1
} // namespace btcpp
