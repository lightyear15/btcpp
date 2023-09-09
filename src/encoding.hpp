#pragma once

#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "bip32.hpp"

namespace btcpp::base58 {
namespace prefix {
constexpr std::array<uint8_t, 1> P2PKH = {0x00};
constexpr std::array<uint8_t, 1> P2SH = {0x05};
constexpr std::array<uint8_t, 1> PrivateKey = {0x80};
constexpr std::array<uint8_t, 4> Bip32PubKey = {0x04, 0x88, 0xB2, 0x1E};
constexpr std::array<uint8_t, 4> Bip32PrivKey = {0x04, 0x88, 0xAD, 0xE4};

} // namespace prefix
enum class Prefix {
    P2PKH,
    P2SH,
    PrivateKey,
    Bip32PubKey,
    Bip32PrivKey,

    P2PKHTestnet,
    P2SHTestnet,
    PrivateKeyTestnet,
};

extern std::map<Prefix, std::span<uint8_t>> Prefixes;

std::vector<uint8_t> decode(std::string_view encoded);
std::string encode(const std::span<uint8_t> &data);

std::vector<uint8_t> decodecheck(std::string_view encoded);
std::string encodecheck(const std::span<uint8_t> &data);
} // namespace btcpp::base58
