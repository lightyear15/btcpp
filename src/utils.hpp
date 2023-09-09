
#pragma once

#include <bit>
#include <concepts>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "bip32.hpp"

namespace bip32 = btcpp::bip32;

namespace btcpp::utils {

std::string to_hex(std::span<uint8_t> input) noexcept;
std::vector<uint8_t> from_hex(std::string_view input);

bip32::MasterKey from_short_seed(const std::vector<uint8_t> &seed);

template <std::integral T> T mybyteswap(T input) noexcept {
    T output = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
        output <<= 8;
        output |= input & 0xff;
        input >>= 8;
    }
    return output;
}

template <std::integral T> T cpu2be(T input) noexcept {
    T output = 0;
    if (std::endian::native == std::endian::big) {
        return input;
    }
    return mybyteswap(input);
}
template <std::integral T> T cpu2le(T input) noexcept {
    T output = 0;
    if (std::endian::native == std::endian::little) {
        return input;
    }
    return mybyteswap(input);
}

template <std::integral T> T be2cpu(T input) noexcept {
    T output = 0;
    if (std::endian::native == std::endian::big) {
        return input;
    }
    return mybyteswap(input);
}
template <std::integral T> T le2cpu(T input) noexcept {
    T output = 0;
    if (std::endian::native == std::endian::little) {
        return input;
    }
    return mybyteswap(input);
}

} // namespace btcpp::utils
