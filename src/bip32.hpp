#pragma once

#include <cstdint>
#include <string>
#include <variant>
#include <array>

#include "bip39/types.hpp"
#include "ec.hpp"

namespace btcpp::bip32 {

using ChainCode = std::array<uint8_t, 32>;
using Bip32Serial = std::array<uint8_t, 78>;

struct MasterKey {
    ec::SecretKey secret;
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
    std::variant<ec::SecretKey, ec::CompressedPublicKey> data;
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
ec::SecretKey to_private_key(const HDKey &key);
ec::PublicKey to_public_key(const HDKey &key);
std::string to_address(const HDKey &key);
} // namespace btcpp::bip32
