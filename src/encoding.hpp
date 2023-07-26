#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "bip32.hpp"

namespace btcpp::base58 {
enum class Prefix: uint8_t {
    BitcoinAddress = 0x00,
    P2SHAddress = 0x05,
    PrivateKey = 0x80,

    BitcoinTestnetAddress = 0x6f,
    P2SHTestnetAddress = 0xc4,
    PrivateTestnetKey = 0xef,
};

std::vector<uint8_t> decode(std::string_view encoded);
std::string encode(const std::span<uint8_t> &data);

const size_t CHECKSUM_SIZE = 4;
std::pair<Prefix, std::vector<uint8_t>> decodecheck(std::string_view encoded);
std::string encodecheck(const std::span<uint8_t>& data, uint8_t version);
} // namespace btcpp::base58
