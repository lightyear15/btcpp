#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <variant>

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
/// from bip39 seed to master
MasterKey to_masterKey(const bip39::Seed &seed);
/// given the network and derivation scheme type the master key is operating, it returns the HDKey
HDKey to_hdKey(const MasterKey &master_key, DerivationScheme scheme = DerivationScheme::BIP44,
               Network network = Network::MAINNET);
/// serialize and deserialize
Bip32Serial serialize(const HDKey &key);
HDKey deserialize(const Bip32Serial &serial);
/// derivation functions
/// keypath example: 
///     - absolute path: ``m/44``: this requires HDKey to be a Master Key
///     - relative path: ``0/1``: HDKey can be at any depth
HDKey derive_prv(const HDKey &key, const std::string &keypath);
HDKey derive_pub(const HDKey &key, const std::string &keypath);
ec::SecretKey to_secretKey(const HDKey &key);
ec::PublicKey to_publicKey(const HDKey &key);
std::string to_address(const HDKey &key);
} // namespace btcpp::bip32
