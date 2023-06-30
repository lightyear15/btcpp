
#include <bitset>
#include <cstdint>

#include "bip39/details.hpp"
#include "utils.hpp"
#include "crypto.hpp"

namespace {
uint8_t checksum(std::span<uint8_t> entropy) {
    btcpp::crypto::SHA256 sha;
    sha.Update(entropy.data(), entropy.size());
    const size_t cksum_size = entropy.size() / 4;
    uint8_t checksum;
    sha.TruncatedFinal(&checksum, 1);
    uint8_t mask = 0xFF << (UINT8_WIDTH - cksum_size);
    return checksum & mask;
}
} // namespace

namespace btcpp::bip39::details {
std::vector<std::string> to_mnemonic(const Dictionary &dictionary, std::vector<uint8_t> entropy) {
    uint8_t cksum = checksum(entropy);
    entropy.push_back(cksum);
    // 11-bit words
    const size_t INDEX_WIDTH = 11;
    std::vector<std::string> mnemonic;
    mnemonic.reserve(entropy.size() * UINT8_WIDTH / INDEX_WIDTH);
    size_t L = 0;
    for (auto idx = 0; idx < entropy.size() - 1; ++idx) {
        uint16_t msb = entropy[idx];
        msb = msb << (L + UINT8_WIDTH);
        uint16_t lsb = entropy[idx + 1];
        lsb = lsb << L;
        lsb += entropy[idx + 2] >> (UINT8_WIDTH - L);
        uint16_t index = msb + lsb;
        index = index >> (UINT16_WIDTH - INDEX_WIDTH);
        mnemonic.push_back(dictionary[index]);

        L += (INDEX_WIDTH - UINT8_WIDTH);
        if (L >= UINT8_WIDTH) {
            ++idx;
        }
        L %= UINT8_WIDTH;
    }
    return mnemonic;
}

} // namespace btcpp::bip39::details
