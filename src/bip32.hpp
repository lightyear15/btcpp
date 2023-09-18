#pragma once

#include <variant>

#include "bip39.hpp"

namespace btcpp::bip32 {

using SecretKey = std::array<uint8_t, 32>;
using PublicKey = std::array<uint8_t, 33>;
using ChainCode = std::array<uint8_t, 32>;
using Bip32Serial = std::array<uint8_t, 78>;

struct MasterKey {
    SecretKey secret;
    ChainCode chain_code;
};

enum class Network {
    MAINNET,
    TESTNET,
};
enum class KeyType {
    PUBLIC,
    PRIVATE,
};
enum class IndexType {
    NORMAL,
    HARDENED,
};
enum class DerivationScheme {
    BIP44,
    BIP49,
    BIP84,
};

struct HDKey {
    DerivationScheme scheme;
    unsigned depth;
    unsigned fingerprint;
    unsigned childnumber;
    ChainCode chaincode;
    std::variant<SecretKey, PublicKey> data;
    Network network;
    std::string keypath;
};

const std::string MASTERKEY_KEY = "Bitcoin seed";
MasterKey to_master_key(const bip39::Seed &seed);
HDKey tohdkey(const MasterKey &master_key, DerivationScheme scheme = DerivationScheme::BIP44, Network network = Network::MAINNET);
Bip32Serial serialize(const HDKey &key);
HDKey deserialize(const Bip32Serial &serial);
HDKey deriveprv(const HDKey &key, const std::string &keypath);
HDKey derivepub(const HDKey &key, const std::string &keypath);
} // namespace btcpp::bip32
