

#include "encoding.hpp"

#include "bip32.hpp"
#include "crypto.hpp"

#include <algorithm>
#include <crypto++/secblockfwd.h>
#include <cstring>
#include <stdexcept>

#include "libbase58.h"
#include <cstdint>

namespace {
extern "C" bool base58_sha256(void *digest, const void *data, size_t data_len) {
    btcpp::crypto::SHA256 hash;
    hash.CalculateDigest(reinterpret_cast<CryptoPP::byte *>(digest), reinterpret_cast<const CryptoPP::byte *>(data), data_len);
    return true;
}
} // namespace
namespace btcpp::base58 {

std::vector<uint8_t> decode(const std::string &encoded, const std::string &prefix) {
    if (encoded.starts_with(prefix) == false) {
        throw std::invalid_argument(std::string("encoded string does not start with prefix ") + prefix);
    }
    auto raw = encoded.substr(0, prefix.size());
    size_t multiplier = 3; // initial multiplier
    std::vector<uint8_t> buffer;
    size_t bsize;
    bool result = false;
    while (result == false) {
        multiplier++;
        buffer.resize(encoded.size() * multiplier + 1);
        bsize = buffer.size();
        result = b58tobin(buffer.data(), &bsize, encoded.c_str(), encoded.size());
    }
    return {std::cbegin(buffer) + buffer.size() - bsize, std::cend(buffer)};
}
std::string encode(const std::span<uint8_t> &data, const std::string &prefix) {
    std::vector<char> buffer;
    size_t bsize;
    size_t multiplier = 0;
    bool result = false;
    while (result == false) {
        multiplier++;
        buffer.resize(data.size() * multiplier + 1);
        bsize = buffer.size();
        result = b58enc(buffer.data(), &bsize, data.data(), data.size());
    }
    return prefix + std::string(buffer.data());
}
} // namespace btcpp::base58
