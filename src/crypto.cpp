
#include "crypto.hpp"

#include <cassert>
#include <iostream>
#include <random>

namespace btcpp {

namespace crypto {
void HASH160Digestor::CalculateDigest(uint8_t *digest, const uint8_t *input, size_t length) {
    SHA256Digestor shaDigestor;
    SHA256 sha;
    shaDigestor.CalculateDigest(sha.data(), input, length);
    RIPEMD160Digestor ripemd160Digestor;
    ripemd160Digestor.CalculateDigest(digest, sha.data(), shaDigestor.DIGESTSIZE);
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

void init() { std::call_once(init_flag, call_once); }

} // namespace secp256k1
} // namespace btcpp
