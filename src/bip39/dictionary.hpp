#pragma once

#include <array>
#include <concepts>
#include <crypto++/lsh.h>
#include <crypto++/pwdbased.h>
#include <span>
#include <string_view>
#include <vector>

namespace btc::bip39::english {
extern const std::array<std::string, 2048> dictionary;
} // namespace btc::bip39::english
