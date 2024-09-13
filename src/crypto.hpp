#pragma once

#include <crypto++/hmac.h>
#include <crypto++/pwdbased.h>
#include <crypto++/ripemd.h>
#include <crypto++/sha.h>

#include <secp256k1.h>

#include "ec.hpp"

namespace btcpp {
namespace crypto {

using SHA256Digestor = CryptoPP::SHA256;
using SHA256 = std::array<uint8_t, SHA256Digestor::DIGESTSIZE>;

using SHA512Digestor = CryptoPP::SHA512;
using SHA512 = std::array<uint8_t, SHA512Digestor::DIGESTSIZE>;

using HMAC512Digestor = CryptoPP::HMAC<CryptoPP::SHA512>;
using HMAC512 = std::array<uint8_t, HMAC512Digestor::DIGESTSIZE>;

using RIPEMD160Digestor = CryptoPP::RIPEMD160;
using RIPEMD160 = std::array<uint8_t, RIPEMD160Digestor::DIGESTSIZE>;

struct HASH160Digestor {
    static void CalculateDigest(uint8_t *digest, const uint8_t *input, size_t length);
    static constexpr size_t DIGESTSIZE = CryptoPP::RIPEMD160::DIGESTSIZE;
};
using HASH160 = std::array<uint8_t, HASH160Digestor::DIGESTSIZE>;

using PBKDF2Digestor = CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512>;

} // namespace crypto

namespace secp256k1 {
extern secp256k1_context *ctx;
extern std::once_flag init_flag;
// be sure to call this function every time you need the context
void init();

} // namespace secp256k1
} // namespace btcpp
