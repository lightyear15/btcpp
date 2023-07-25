#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "bip32.hpp"

namespace btcpp::base58 {
std::vector<uint8_t> decode(std::string_view encoded, const std::string &prefix = {});
std::string encode(const std::span<uint8_t> &data, const std::string &prefix = {});

std::vector<uint8_t> decodecheck(std::string_view encoded, const std::string& prefix = {});
std::string encodecheck(const std::span<uint8_t>& data, uint8_t version, const std::string& prefix = {});
} // namespace btcpp::base58
