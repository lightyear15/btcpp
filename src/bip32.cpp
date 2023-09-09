
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <cstdint>
#include <iterator>
#include <map>
#include <secp256k1.h>
#include <type_traits>
#include <utility>
#include <variant>

#include "bip32.hpp"
#include "crypto.hpp"
#include "utils.hpp"

namespace btcpp::bip32 {

namespace {

const std::map<std::pair<Network, KeyType>, uint32_t> version{
    {{Network::MAINNET, KeyType::PUBLIC}, 0x0488b21e},
    {{Network::MAINNET, KeyType::PRIVATE}, 0x0488ade4},
    {{Network::TESTNET, KeyType::PUBLIC}, 0x043587cf},
    {{Network::TESTNET, KeyType::PRIVATE}, 0x04358394},
};

struct SerializeDataVisitor {
    uint8_t *buffer;
    size_t sized = 0;
    void operator()(const PublicKey &data) {
        std::copy(std::cbegin(data), std::cend(data), buffer);
        sized = data.size();
    }
    void operator()(const SecretKey &data) {
        buffer[0] = 0;
        std::copy(std::cbegin(data), std::cend(data), buffer + 1);
        sized = data.size() + 1;
    }
};

struct GetPublicKeyVisitor {
    GetPublicKeyVisitor() { secp256k1::init(); }
    PublicKey operator()(const PublicKey &data) { return data; }
    PublicKey operator()(const SecretKey &secret) { return secp256k1::getpublickey(secret); }
};

std::pair<SecretKey, ChainCode> ckdpriv(const SecretKey &secret, const ChainCode &chain, uint32_t index) {
    crypto::HMAC512 hmac(chain.data(), chain.size());
    std::vector<uint8_t> buffer;
    ;
    if (index >= 0x80000000) {
        buffer.push_back(0);
        std::copy(std::cbegin(secret), std::cend(secret), std::back_inserter(buffer));
        index = utils::cpu2be(index);
        auto *indexIt = reinterpret_cast<uint8_t *>(&index);
        std::copy(indexIt, indexIt + sizeof(index), std::back_inserter(buffer));
    } else {
        PublicKey data = secp256k1::getpublickey(secret);
        std::copy(std::cbegin(data), std::cend(data), std::back_inserter(buffer));
    }
    std::array<uint8_t, hmac.DIGESTSIZE> digest;
    hmac.CalculateDigest(digest.data(), buffer.data(), buffer.size());
    const auto *digestIt = std::cbegin(digest);
    SecretKey newsecret;
    ChainCode newchain;
    std::copy_n(digestIt, newsecret.size(), std::begin(newsecret));
    digestIt += newsecret.size();

    int res = secp256k1_ec_seckey_tweak_add(secp256k1::ctx, newsecret.data(), secret.data());
    assert(res == 1);

    std::copy_n(digestIt, newchain.size(), std::begin(newchain));
    return {newsecret, newchain};
}

std::pair<PublicKey, ChainCode> ckdpub(const SecretKey &secret, const ChainCode &chain, uint32_t index) {
    auto [newsecret, newchain] = ckdpriv(secret, chain, index);
    auto newdata = secp256k1::getpublickey(newsecret);
    return {newdata, newchain};
}

HDKey deriveprv(const HDKey &key, uint32_t index, IndexType type) {
    assert(index < 0x80000000);
    assert(std::holds_alternative<SecretKey>(key.data));

    index += (type == IndexType::HARDENED) ? 0x80000000 : 0;
    const auto &secret = std::get<SecretKey>(key.data);
    auto [newsecret, newchain] = ckdpriv(secret, key.chaincode, index);
    PublicKey data = secp256k1::getpublickey(secret);
    std::array<uint8_t, crypto::HASH160::DIGESTSIZE> digest;
    crypto::HASH160::CalculateDigest(digest.data(), data.data(), data.size());
    uint32_t fingerprint = utils::be2cpu(*reinterpret_cast<uint32_t *>(digest.data()));

    HDKey derived{
        .depth = key.depth + 1,
        .fingerprint = fingerprint,
        .childnumber = index,
        .chaincode = newchain,
        .data = newsecret,
        .network = key.network,
        .keypath = key.keypath + "/" + std::to_string(index) + (type == IndexType::HARDENED ? "'" : ""),
    };
    return derived;
}

} // namespace
//
MasterKey to_master_key(const bip39::Seed &seed) {
    crypto::HMAC512 hmac(CryptoPP::ConstBytePtr(MASTERKEY_KEY));
    MasterKey master_key;
    std::array<uint8_t, master_key.secret.size() + master_key.chain_code.size()> digest;
    static_assert(digest.size() == crypto::HMAC512::DIGESTSIZE, "digest size mismatch");
    hmac.CalculateDigest(digest.data(), seed.data(), seed.size());
    const auto *digestIt = std::cbegin(digest);
    std::copy_n(digestIt, master_key.secret.size(), std::begin(master_key.secret));
    digestIt += master_key.secret.size();
    std::copy_n(digestIt, master_key.chain_code.size(), std::begin(master_key.chain_code));
    return master_key;
}

HDKey tohdkey(const MasterKey &master_key, Network network) {
    HDKey hdkey{
        .depth = 0,
        .fingerprint = 0,
        .childnumber = 0,
        .chaincode = master_key.chain_code,
        .data = master_key.secret,
        .network = network,
        .keypath = {},
    };
    return hdkey;
}

Bip32Serial serialize(const HDKey &key) {
    Bip32Serial serial;
    size_t cursor = 0;

    auto *versionbytes = reinterpret_cast<uint32_t *>(&serial[cursor]);
    cursor += sizeof(*versionbytes);
    auto type = std::holds_alternative<SecretKey>(key.data) ? KeyType::PRIVATE : KeyType::PUBLIC;
    auto dictkey = std::pair<Network, KeyType>{key.network, type};
    *versionbytes = utils::cpu2be(version.at(dictkey));
    serial[cursor++] = key.depth;

    auto *fingerprint = reinterpret_cast<uint32_t *>(&serial[cursor]);
    cursor += sizeof(*fingerprint);
    *fingerprint = utils::cpu2be(key.fingerprint);

    auto *childnumber = reinterpret_cast<uint32_t *>(&serial[cursor]);
    cursor += sizeof(*childnumber);
    *childnumber = utils::cpu2be(key.childnumber);

    std::copy(std::cbegin(key.chaincode), std::cend(key.chaincode), std::begin(serial) + cursor);
    cursor += key.chaincode.size();

    SerializeDataVisitor lizer{.buffer = &serial[cursor]};
    std::visit(lizer, key.data);
    cursor += lizer.sized;
    return serial;
}

HDKey deserialize(const Bip32Serial &serial) {
    HDKey key;
    size_t cursor = 0;
    uint32_t versionbytes = utils::be2cpu(*reinterpret_cast<const uint32_t *>(&serial[cursor]));
    cursor += sizeof(versionbytes);
    KeyType type;
    for (const auto &[dictkey, dictvalue] : version) {
        if (dictvalue == versionbytes) {
            key.network = dictkey.first;
            type = dictkey.second;
            break;
        }
    }
    key.depth = serial[cursor++];
    key.fingerprint = utils::be2cpu(*reinterpret_cast<const uint32_t *>(&serial[cursor]));
    cursor += sizeof(key.fingerprint);
    key.childnumber = utils::be2cpu(*reinterpret_cast<const uint32_t *>(&serial[cursor]));
    cursor += sizeof(key.childnumber);
    std::copy_n(std::cbegin(serial) + cursor, key.chaincode.size(), std::begin(key.chaincode));
    cursor += key.chaincode.size();
    switch (type) {
    case KeyType::PRIVATE:
        SecretKey secret;
        std::copy_n(std::cbegin(serial) + cursor + 1, secret.size(), std::begin(secret));
        key.data = secret;
        break;
    case KeyType::PUBLIC:
        PublicKey data;
        std::copy_n(std::cbegin(serial) + cursor, data.size(), std::begin(data));
        break;
    }
    return key;
}

HDKey deriveprv(const HDKey &key, const std::string &keypath) {
    secp256k1::init();
    auto type = std::holds_alternative<SecretKey>(key.data) ? KeyType::PRIVATE : KeyType::PUBLIC;
    if (type != KeyType::PRIVATE) {
        throw std::invalid_argument("can't derive a private key from a public one");
    }
    if (keypath.empty()) {
        return key;
    }

    HDKey derived = key;
    std::vector<std::string> paths;
    boost::split(paths, keypath, boost::is_any_of("/"));
    for (const auto &path : paths) {
        const IndexType hardened = path.back() == '\'' ? IndexType::HARDENED : IndexType::NORMAL;
        const std::string indexstr = hardened == IndexType::HARDENED ? path.substr(0, path.size() - 1) : path;
        uint32_t index = std::stoul(indexstr);
        derived = deriveprv(derived, index, hardened);
    }
    return derived;
}
HDKey derivepub(const HDKey &key, const std::string &keypath) {
    secp256k1::init();

    if (keypath.empty()) {
        HDKey derived = key;
        derived.data = std::visit(GetPublicKeyVisitor(), derived.data);
        return derived;
    }

    auto type = std::holds_alternative<SecretKey>(key.data) ? KeyType::PRIVATE : KeyType::PUBLIC;
    std::vector<std::string> paths;
    boost::split(paths, keypath, boost::is_any_of("/"));
    switch (type) {
    case KeyType::PRIVATE: {
        HDKey derived = deriveprv(key, keypath);
        derived.data = std::visit(GetPublicKeyVisitor(), derived.data);
        return derived;
    }
    case KeyType::PUBLIC:
        throw std::invalid_argument("not implemented");
        return {};
    }
    return {};
}
} // namespace btcpp::bip32
