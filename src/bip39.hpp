#pragma once

#include <span>
#include <string>

#include "bip39/details.hpp"
#include "bip39/types.hpp"

namespace btcpp::bip39 {

template <typename E>
requires entropy<E> E generate() {
    E entropy;
    details::generate(std::span<uint8_t>(entropy.begin(), entropy.end()));
    return entropy;
}

template <typename E>
requires entropy<E> std::vector<std::string> to_mnemonic(const Dictionary &dictionary, E entropy) {
    return details::to_mnemonic(dictionary, std::span<const uint8_t>(entropy));
}

Seed to_seed(const std::vector<std::string> &mnemonic, std::string_view passphrase = "");
Seed from_raw(const std::vector<uint8_t> &seed);

} // namespace btcpp::bip39
