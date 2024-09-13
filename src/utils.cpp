
#include "utils.hpp"
#include "crypto.hpp"

#include <boost/algorithm/hex.hpp>

namespace btcpp::utils {

std::string to_hex(std::span<uint8_t> in) noexcept {
    std::string out;
    boost::algorithm::hex_lower(std::cbegin(in), std::cend(in), std::back_inserter(out));
    return out;
}

std::vector<uint8_t> from_hex(std::string_view in) {
    std::vector<uint8_t> out;
    out.reserve(in.size() / 2);
    boost::algorithm::unhex(std::cbegin(in), std::cend(in), std::back_inserter(out));
    return out;
}

bip32::MasterKey from_short_seed(const std::vector<uint8_t> &seed) {
    crypto::HMAC512Digestor hmac(CryptoPP::ConstBytePtr(bip32::MASTERKEY_KEY));
    bip32::MasterKey master_key;
    std::array<uint8_t, master_key.secret.size() + master_key.chain_code.size()> digest;
    static_assert(digest.size() == crypto::HMAC512Digestor::DIGESTSIZE, "digest size mismatch");
    hmac.CalculateDigest(digest.data(), seed.data(), seed.size());
    const auto *digestIt = std::cbegin(digest);
    std::copy_n(digestIt, master_key.secret.size(), std::begin(master_key.secret));
    digestIt += master_key.secret.size();
    std::copy_n(digestIt, master_key.chain_code.size(), std::begin(master_key.chain_code));
    return master_key;
}
} // namespace btcpp::utils
