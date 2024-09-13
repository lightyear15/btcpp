
#include <boost/algorithm/string/join.hpp>
#include <crypto++/secblockfwd.h>
#include <stdexcept>

#include "bip39.hpp"
#include "crypto.hpp"

namespace btcpp::bip39 {
Seed to_seed(const std::vector<std::string> &mnemonic, std::string_view passphrase) {
    crypto::PBKDF2Digestor pbkdf2;
    std::string mnemonicPhrase = boost::algorithm::join(mnemonic, " ");
    std::string salt = std::string("mnemonic") + std::string(passphrase);
    Seed seed;
    CryptoPP::SecByteBlock seedblock(seed.size());
    pbkdf2.DeriveKey(seedblock.BytePtr(), seedblock.size(), 0, CryptoPP::ConstBytePtr(mnemonicPhrase), mnemonicPhrase.size(),
                     CryptoPP::ConstBytePtr(salt), salt.size(), 2048);
    std::copy(std::cbegin(seedblock), std::cend(seedblock), std::begin(seed));
    return seed;
}

Seed from_raw(const std::vector<uint8_t> &raw_seed) {
    Seed seed;
    if (seed.size() != raw_seed.size()) {
        throw std::invalid_argument("Invalid seed size");
    }
    std::copy(std::cbegin(raw_seed), std::cend(raw_seed), std::begin(seed));
    return seed;
}
} // namespace btcpp::bip39
