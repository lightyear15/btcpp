
#include "ec.hpp"

#include <cassert>

#include "crypto.hpp"

namespace btcpp::ec {

CompressedPublicKey get_public_key(SpanSecretKey secret) {
    secp256k1_pubkey pubkey;
    int res = secp256k1_ec_pubkey_create(secp256k1::ctx, &pubkey, secret.data());
    assert(res == 1);
    std::array<uint8_t, 33> data;
    size_t outlen = data.size();
    secp256k1_ec_pubkey_serialize(secp256k1::ctx, data.data(), &outlen, &pubkey, SECP256K1_EC_COMPRESSED);
    assert(outlen == data.size());
    return data;
}
void to_address(const SpanPublicKey &public_key) {}
} // namespace btcpp::ec
