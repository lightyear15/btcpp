

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

std::string_view check_and_remove_prefix(std::string_view input, const std::string& prefix) {
    if (!input.starts_with(prefix)) {
        throw std::invalid_argument(std::string("input string does not start with prefix ") + prefix);
    }
    input.remove_prefix(prefix.size());
    return input;
}


} // namespace
namespace btcpp::base58 {
using std::string;

std::vector<uint8_t> decode(std::string_view encoded, const std::string &prefix) {
    std::string_view unprefixed = check_and_remove_prefix(encoded, prefix);
    std::vector<uint8_t> buffer;
    // initial buffer has the size of encoded.size() * multiplier (+ 1 in case encoded.size() == 0)
    // we keep increasing the size of the buffer by increasing the multiplier until b58tobin returns OK
    size_t multiplier = 3;
    size_t bsize;
    bool result = false;
    while (!result) {
        multiplier++;
        buffer.resize(unprefixed.size() * multiplier + 1);
        bsize = buffer.size();
        result = b58tobin(buffer.data(), &bsize, unprefixed.c_str(), unprefixed.size());
    }
    // b58tobin places the decoded data at the end of the buffer
    return {std::cbegin(buffer) + buffer.size() - bsize, std::cend(buffer)};
}
string encode(const std::span<uint8_t> &data, const std::string &prefix) {
    // initial buffer has the size of encoded.size() * multiplier (+ 1 in case encoded.size() == 0)
    // we keep increasing the size of the buffer by increasing the multiplier until b58tobin returns OK
    std::vector<char> buffer;
    size_t bsize;
    size_t multiplier = 1;
    bool result = false;
    while (!result) {
        multiplier++;
        buffer.resize(data.size() * multiplier + 1); // (+ 1) in case data.size() == 0
        bsize = buffer.size();
        result = b58enc(buffer.data(), &bsize, data.data(), data.size());
    }
    return prefix + std::string(buffer.data());
}

std::vector<uint8_t> decodecheck(const std::string &encoded, const std::string &prefix) {
    std::string_view unprefixed = check_and_remove_prefix(encoded, prefix);
    const auto decoded = decode(unprefixed, "");
    int checkresult = b58check(decoded.data(), decoded.size(), unprefixed.data(), unprefixed.size());
    if (checkresult < 0) {
        throw std::invalid_argument("invalid base58 checksum");
    }
    return decoded;
}
std::string encodecheck(const std::span<uint8_t> &data, uint8_t version, const std::string &prefix) { return {}; }
} // namespace btcpp::base58
