#include <array>
#include <random>
#include <span>
#include <string>

#include "bip39/details.hpp"
#include "bip39/types.hpp"

namespace btc::bip39 {

template <typename E>
requires entropy<E> E generate() {
    E entropy;
    std::independent_bits_engine<std::random_device, UINT8_WIDTH, uint8_t> rng;
    std::generate(std::begin(entropy), std::end(entropy), std::ref(rng));
    return entropy;
}
template <typename E>
requires entropy<E> std::vector<std::string> to_mnemonic(const Dictionary &dictionary, E entropy) {
    return details::to_mnemonic(dictionary, std::span<E>(entropy));
}

Seed to_seed(const std::vector<std::string> &mnemonic, std::string_view passphrase = "");

} // namespace btc::bip39
