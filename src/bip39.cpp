
#include <boost/algorithm/string/join.hpp>
#include <crypto++/pwdbased.h>
#include <crypto++/sha.h>

namespace btc::bip39 {
std::array<uint8_t, 64> to_seed(const std::vector<std::string> &mnemonic, std::string_view passphrase) {
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA512> pbkdf2;
    std::array<uint8_t, 64> seed;
    std::string mnemonicPhrase = boost::algorithm::join(mnemonic, " ");
    std::string salt = std::string("mnemonic") + std::string(passphrase);
    pbkdf2.DeriveKey(reinterpret_cast<unsigned char *>(seed.data()), seed.size(), 0, reinterpret_cast<unsigned char *>(mnemonicPhrase.data()),
                     mnemonicPhrase.size(), reinterpret_cast<unsigned char *>(salt.data()), salt.size(), 2048);
    return seed;
}
} // namespace btc::bip39
