#include <crypto++/misc.h>
#include <type_traits>

#include "bip32.hpp"
#include "crypto.hpp"

namespace btcpp::bip32 {

MasterKey to_master_key(const bip39::Seed &seed) {
    crypto::HMAC512 hmac(CryptoPP::ConstBytePtr(MASTERKEY_KEY));
    MasterKey master_key;
    std::array<uint8_t, master_key.secret.size() + master_key.chain_code.size()> digest;
    static_assert(digest.size() == crypto::HMAC512::DIGESTSIZE, "digest size mismatch");
    hmac.CalculateDigest(digest.data(),seed.data(), seed.size());
    const auto *digestIt = std::cbegin(digest);
    std::copy_n(digestIt, master_key.secret.size(), std::begin(master_key.secret));
    digestIt += master_key.secret.size();
    std::copy_n(digestIt, master_key.chain_code.size(), std::begin(master_key.chain_code));
    return master_key;
}

} // namespace btcpp::bip32
