#pragma once

#include <variant>

#include "bip32.hpp"

namespace btcpp::address {
struct P2PK {
    btcpp::bip32::PublicKey key;
};
struct P2PKH {
    btcpp::bip32::PublicKey key;
};
struct P2WPKH {
    btcpp::bip32::PublicKey key;
};
struct P2SH {};
struct P2WSH {};
struct P2TR {};

using Address = std::variant<P2PK, P2PKH, P2WPKH, P2SH, P2WSH, P2TR>;

} // namespace btcpp::address
