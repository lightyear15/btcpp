
#include "crypto.hpp"

#include <cassert>
#include <iostream>

namespace btcpp {

namespace crypto {
void HASH160::CalculateDigest(uint8_t *digest, const uint8_t *input, size_t length) {
    SHA256 sha;
    std::array<uint8_t, sha.DIGESTSIZE> sha_digest;
    sha.CalculateDigest(sha_digest.data(), input, length);
    CryptoPP::RIPEMD160().CalculateDigest(digest, sha_digest.data(), sha.DIGESTSIZE);
}
} // namespace crypto

namespace secp256k1 {

secp256k1_context *ctx;
std::once_flag init_flag;

namespace {

void call_once() {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    std::random_device r;
    std::array<uint8_t, 32> seed;
    std::generate(std::begin(seed), std::end(seed), [&r]() { return r(); });
    int res = secp256k1_context_randomize(ctx, seed.data());
    assert(res == 1);
    res = std::atexit([]() { secp256k1_context_destroy(ctx); });
    if (res != 0) {
        std::cout << "cannot register secp256k1 context destroy function" << std::endl;
        std::abort();
    }
}
} // namespace
//
void init() {
    std::call_once(init_flag, call_once);
}
std::array<uint8_t, 33> getpublickey(const std::array<uint8_t, 32> &secret) {
    secp256k1_pubkey pubkey;
    int res = secp256k1_ec_pubkey_create(secp256k1::ctx, &pubkey, secret.data());
    assert(res == 1);
    std::array<uint8_t, 33> data;
    size_t outlen = data.size();
    secp256k1_ec_pubkey_serialize(secp256k1::ctx, data.data(), &outlen, &pubkey, SECP256K1_EC_COMPRESSED);
    assert(outlen == data.size());
    return data;
}
} // namespace secp256k1
} // namespace btcpp
