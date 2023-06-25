#pragma once

#include <array>
#include <string>
#include <concepts>

namespace btc::bip39 {

using Dictionary = std::array<std::string, 2048>;
using Seed = std::array<uint8_t, 64>;

using Entropy128 = std::array<uint8_t, 16>;
using Entropy160 = std::array<uint8_t, 20>;
using Entropy192 = std::array<uint8_t, 24>;
using Entropy224 = std::array<uint8_t, 28>;
using Entropy256 = std::array<uint8_t, 32>;


template <typename E>
concept entropy = std::same_as<E, Entropy128> || std::same_as<E, Entropy160> || std::same_as<E, Entropy192> || std::same_as<E, Entropy224> ||
    std::same_as<E, Entropy256>;

}
