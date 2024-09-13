
#include "encoding.hpp"

#include "bip32.hpp"
#include "crypto.hpp"

#include <algorithm>
#include <array>
#include <crypto++/secblockfwd.h>
#include <cstring>
#include <span>
#include <stdexcept>

#include "libbase58.h"
#include <cstdint>
#include <string_view>

const size_t CHECKSUM_SIZE = 4;

namespace {
extern "C" {
bool base58_sha256(void *digest, const void *data, size_t data_len) {
    btcpp::crypto::SHA256Digestor hash;
    hash.CalculateDigest(reinterpret_cast<CryptoPP::byte *>(digest), reinterpret_cast<const CryptoPP::byte *>(data), data_len);
    return true;
}
} // extern "C"
} // namespace
namespace btcpp::base58 {
using std::string;

std::vector<uint8_t> decode(std::string_view encoded) {
    std::vector<uint8_t> buffer;
    // initial buffer has the size of encoded.size() * multiplier (+ 1 in case encoded.size() == 0)
    // we keep increasing the size of the buffer by increasing the multiplier until b58tobin returns OK
    size_t multiplier = 3;
    size_t bsize;
    bool result = false;
    while (!result) {
        multiplier++;
        buffer.resize(encoded.size() * multiplier + 1);
        bsize = buffer.size();
        result = b58tobin(buffer.data(), &bsize, encoded.data(), encoded.size());
    }
    // b58tobin places the decoded data at the end of the buffer
    return {std::cbegin(buffer) + buffer.size() - bsize, std::cend(buffer)};
}
std::string encode(std::span<const uint8_t> data) {
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
    buffer.resize(bsize);
    return {buffer.data()};
}

namespace internal {

std::pair<Prefix, std::vector<uint8_t>> decodecheck(std::string_view encoded) {
    std::vector<uint8_t> decoded = decode(encoded);
    b58_sha256_impl = base58_sha256;
    int checkresult = b58check(decoded.data(), decoded.size(), encoded.data(), encoded.size());
    if (checkresult < 0) {
        throw std::invalid_argument("invalid checksum");
    }
    decoded.resize(decoded.size() - CHECKSUM_SIZE);
    return {static_cast<Prefix>(checkresult), decoded};
}

std::string encodecheck(std::span<const uint8_t> data, uint8_t version) {
    b58_sha256_impl = base58_sha256;
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
        result = b58check_enc(buffer.data(), &bsize, version, data.data(), data.size());
    }
    buffer.resize(bsize);
    return {buffer.data()};
}
} // namespace internal

std::vector<uint8_t> decodecheck(std::string_view encoded) { return internal::decodecheck(encoded).second; }
std::string encodecheck(std::span<const uint8_t> data) { return internal::encodecheck(std::span(data.begin() + 1, data.end()), data[0]); }

namespace bip32 {

btcpp::bip32::Bip32Serial decode(std::string_view encoded) {
    std::vector<uint8_t> decoded = base58::decodecheck(encoded);
    btcpp::bip32::Bip32Serial serial;
    if (decoded.size() != serial.size()) {
        throw std::invalid_argument("invalid bip32 serial size");
    }
    std::copy(std::cbegin(decoded), std::cend(decoded), std::begin(serial));
    return serial;
}
std::string encode(const btcpp::bip32::Bip32Serial &serial) { return base58::encodecheck(std::span(serial)); }

} // namespace bip32
} // namespace btcpp::base58
