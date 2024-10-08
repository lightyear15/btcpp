
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/functional/hash.hpp>
#include <map>
#include <stdexcept>
#include <unordered_map>
#include <utility>

#include "bip32.hpp"
#include "crypto.hpp"
#include "ec.hpp"
#include "utils.hpp"

namespace btcpp::bip32 {

namespace {

struct VersionKey {
    Network network;
    KeyType type;
    DerivationScheme scheme;
    bool operator==(const VersionKey &other) const {
        return network == other.network and type == other.type and scheme == other.scheme;
    }
};
struct VersionKeyHash {
    std::size_t operator()(const VersionKey &key) const {
        std::size_t seed = 0;
        boost::hash_combine(seed, key.network);
        boost::hash_combine(seed, key.type);
        boost::hash_combine(seed, key.scheme);
        return seed;
    }
};
const std::unordered_map<VersionKey, uint32_t, VersionKeyHash> version{
    {{Network::MAINNET, KeyType::PUBLIC, DerivationScheme::BIP44}, 0x0488b21e},
    {{Network::MAINNET, KeyType::PRIVATE, DerivationScheme::BIP44}, 0x0488ade4},
    {{Network::TESTNET, KeyType::PUBLIC, DerivationScheme::BIP44}, 0x043587cf},
    {{Network::TESTNET, KeyType::PRIVATE, DerivationScheme::BIP44}, 0x04358394},

    {{Network::MAINNET, KeyType::PUBLIC, DerivationScheme::BIP49}, 0x049d7cb2},
    {{Network::MAINNET, KeyType::PRIVATE, DerivationScheme::BIP49}, 0x049d7878},
    {{Network::TESTNET, KeyType::PUBLIC, DerivationScheme::BIP49}, 0x044a5262},
    {{Network::TESTNET, KeyType::PRIVATE, DerivationScheme::BIP49}, 0x044a4e28},

    {{Network::MAINNET, KeyType::PUBLIC, DerivationScheme::BIP84}, 0x04b24746},
    {{Network::MAINNET, KeyType::PRIVATE, DerivationScheme::BIP84}, 0x04b2430c},
    {{Network::TESTNET, KeyType::PUBLIC, DerivationScheme::BIP84}, 0x045f1cf6},
    {{Network::TESTNET, KeyType::PRIVATE, DerivationScheme::BIP84}, 0x045f18bc},
};

struct SerializeDataVisitor {
    uint8_t *buffer;
    size_t sized = 0;
    void operator()(const ec::CompressedPublicKey &data) {
        std::copy(std::cbegin(data), std::cend(data), buffer);
        sized = data.size();
    }
    void operator()(const ec::SecretKey &data) {
        buffer[0] = 0;
        std::copy(std::cbegin(data), std::cend(data), buffer + 1);
        sized = data.size() + 1;
    }
};

struct GetPublicKeyVisitor {
    GetPublicKeyVisitor() { secp256k1::init(); }
    ec::CompressedPublicKey operator()(const ec::CompressedPublicKey &data) { return data; }
    ec::CompressedPublicKey operator()(const ec::SecretKey &secret) { return ec::get_public_key(secret); }
};

std::pair<ec::SecretKey, ChainCode> ckdpriv(const ec::SecretKey &secret, const ChainCode &chain, uint32_t index) {
    crypto::HMAC512Digestor hmac(chain.data(), chain.size());
    std::vector<uint8_t> buffer;
    ;
    if (index >= 0x80000000) {
        buffer.push_back(0);
        std::copy(std::cbegin(secret), std::cend(secret), std::back_inserter(buffer));
    } else {
        ec::CompressedPublicKey data = ec::get_public_key(secret);
        std::copy(std::cbegin(data), std::cend(data), std::back_inserter(buffer));
    }
    index = utils::cpu2be(index);
    auto *indexIt = reinterpret_cast<uint8_t *>(&index);
    std::copy(indexIt, indexIt + sizeof(index), std::back_inserter(buffer));
    std::array<uint8_t, hmac.DIGESTSIZE> digest;
    hmac.CalculateDigest(digest.data(), buffer.data(), buffer.size());
    const auto *digestIt = std::cbegin(digest);
    ec::SecretKey newsecret;
    ChainCode newchain;
    std::copy_n(digestIt, newsecret.size(), std::begin(newsecret));
    digestIt += newsecret.size();

    int res = secp256k1_ec_seckey_tweak_add(secp256k1::ctx, newsecret.data(), secret.data());
    assert(res == 1);

    std::copy_n(digestIt, newchain.size(), std::begin(newchain));
    return {newsecret, newchain};
}

std::pair<ec::CompressedPublicKey, ChainCode> ckdpub(const ec::SecretKey &secret, const ChainCode &chain,
                                                     uint32_t index) {
    auto [newsecret, newchain] = ckdpriv(secret, chain, index);
    auto newdata = ec::get_public_key(newsecret);
    return {newdata, newchain};
}

HDKey deriveprv(const HDKey &key, uint32_t index, IndexType type) {
    assert(index < 0x80000000);
    assert(std::holds_alternative<ec::SecretKey>(key.data));

    index += (type == IndexType::HARDENED) ? 0x80000000 : 0;
    const auto &secret = std::get<ec::SecretKey>(key.data);
    auto [newsecret, newchain] = ckdpriv(secret, key.chaincode, index);
    ec::CompressedPublicKey data = ec::get_public_key(secret);
    crypto::HASH160 digest;
    crypto::HASH160Digestor::CalculateDigest(digest.data(), data.data(), data.size());
    uint32_t fingerprint = utils::be2cpu(*reinterpret_cast<uint32_t *>(digest.data()));

    HDKey derived{
        .scheme = key.scheme,
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
MasterKey to_masterKey(const bip39::Seed &seed) {
    crypto::HMAC512Digestor hmac(CryptoPP::ConstBytePtr(MASTERKEY_KEY));
    MasterKey master_key;
    std::array<uint8_t, master_key.secret.size() + master_key.chain_code.size()> digest;
    static_assert(digest.size() == crypto::HMAC512Digestor::DIGESTSIZE, "digest size mismatch");
    hmac.CalculateDigest(digest.data(), seed.data(), seed.size());
    const auto *digestIt = std::cbegin(digest);
    std::copy_n(digestIt, master_key.secret.size(), std::begin(master_key.secret));
    digestIt += master_key.secret.size();
    std::copy_n(digestIt, master_key.chain_code.size(), std::begin(master_key.chain_code));
    return master_key;
}

HDKey to_hdKey(const MasterKey &master_key, DerivationScheme scheme, Network network) {
    HDKey hdkey{
        .scheme = scheme,
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
    auto type = std::holds_alternative<ec::SecretKey>(key.data) ? KeyType::PRIVATE : KeyType::PUBLIC;
    VersionKey dictkey{key.network, type, key.scheme};
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
    secp256k1::init();
    HDKey key;
    const auto *cursor = std::begin(serial);
    uint32_t versionbytes = utils::be2cpu(*reinterpret_cast<const uint32_t *>(cursor));
    cursor += sizeof(versionbytes);
    auto foundIt = std::find_if(std::cbegin(version), std::cend(version),
                                [&](const auto &dict) { return dict.second == versionbytes; });
    if (foundIt == std::cend(version)) {
        throw std::invalid_argument("unknown extended key version");
    }
    key.network = foundIt->first.network;
    auto type = foundIt->first.type;
    key.scheme = foundIt->first.scheme;
    key.depth = *cursor++;
    key.fingerprint = utils::be2cpu(*reinterpret_cast<const uint32_t *>(cursor));
    if (key.depth == 0 and key.fingerprint != 0) {
        throw std::invalid_argument("zero depth with non-zero parent fingerprint");
    }
    cursor += sizeof(key.fingerprint);
    key.childnumber = utils::be2cpu(*reinterpret_cast<const uint32_t *>(cursor));
    if (key.depth == 0 and key.childnumber != 0) {
        throw std::invalid_argument("zero depth with non-zero index");
    }
    cursor += sizeof(key.childnumber);
    std::copy_n(cursor, key.chaincode.size(), std::begin(key.chaincode));
    cursor += key.chaincode.size();
    switch (type) {
    case KeyType::PRIVATE: {
        ec::SecretKey secret;
        if (*cursor != 0) {
            throw std::invalid_argument("prvkey version / pubkey mismatch");
        }
        std::copy_n(++cursor, secret.size(), std::begin(secret));
        int res = secp256k1_ec_seckey_verify(secp256k1::ctx, secret.data());
        if (res != 1) {
            throw std::invalid_argument("invalid prvkey");
        }
        key.data = secret;
    } break;
    case KeyType::PUBLIC: {
        if (*cursor == 0) {
            throw std::invalid_argument("pubkey version / prvkey mismatch");
        }
        ec::CompressedPublicKey data;
        secp256k1_pubkey pubkey;
        int res = secp256k1_ec_pubkey_parse(secp256k1::ctx, &pubkey, cursor, data.size());
        if (res != 1) {
            throw std::invalid_argument("invalid pubkey");
        }
        size_t len = data.size();
        res = secp256k1_ec_pubkey_serialize(secp256k1::ctx, data.data(), &len, &pubkey, SECP256K1_EC_COMPRESSED);
        assert(res == 1);
        key.data = data;
    } break;
    }
    return key;
}

HDKey derive_prv(const HDKey &key, const std::string &keypath) {
    secp256k1::init();
    auto type = std::holds_alternative<ec::SecretKey>(key.data) ? KeyType::PRIVATE : KeyType::PUBLIC;
    if (type != KeyType::PRIVATE) {
        throw std::invalid_argument("can't derive a private key from a public one");
    }
    if (keypath.empty()) {
        return key;
    }

    HDKey derived = key;
    std::vector<std::string> paths;
    boost::split(paths, keypath, boost::is_any_of("/"));
    if (paths[0] == "m") {
        if (key.depth != 0 or key.fingerprint != 0 or key.childnumber != 0) {
            throw std::invalid_argument("key is not master key");
        }
        paths.erase(paths.begin());
    }
    for (const auto &path : paths) {
        const IndexType hardened = path.back() == '\'' ? IndexType::HARDENED : IndexType::NORMAL;
        const std::string indexstr = hardened == IndexType::HARDENED ? path.substr(0, path.size() - 1) : path;
        uint32_t index = std::stoul(indexstr);
        derived = deriveprv(derived, index, hardened);
    }
    return derived;
}
HDKey derive_pub(const HDKey &key, const std::string &keypath) {
    secp256k1::init();

    if (keypath.empty()) {
        HDKey derived = key;
        derived.data = std::visit(GetPublicKeyVisitor(), derived.data);
        return derived;
    }

    auto type = std::holds_alternative<ec::SecretKey>(key.data) ? KeyType::PRIVATE : KeyType::PUBLIC;
    std::vector<std::string> paths;
    boost::split(paths, keypath, boost::is_any_of("/"));
    switch (type) {
    case KeyType::PRIVATE: {
        HDKey derived = derive_prv(key, keypath);
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
