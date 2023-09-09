
#include <gtest/gtest-matchers.h>
#include <gtest/gtest.h>

#include <gtest/internal/gtest-param-util.h>
#include <iostream>

#include "bip32.hpp"
#include "bip39.hpp"
#include "encoding.hpp"
#include "utils.hpp"

#include "data/testvectors.hpp"

namespace b58 = btcpp::base58;
namespace b39 = btcpp::bip39;
namespace b32 = btcpp::bip32;
namespace t39 = test::bip39;
namespace t32 = test::bip32;

namespace test::bip32 {
class Bip39VectorTesting_B : public ::testing::TestWithParam<t39::Data> {};
TEST_P(Bip39VectorTesting_B, to_master_key) {
    auto data = GetParam();
    auto seed = b39::from_raw(btcpp::utils::from_hex(data.seed));
    auto decoded = b58::decodecheck(data.master_key);

    auto master_key = b32::to_master_key(seed);
    auto hdkey = b32::tohdkey(master_key, b32::Network::MAINNET);
    auto bip32serial = b32::serialize(hdkey);
    std::vector<uint8_t> actual{bip32serial.begin(), bip32serial.end()};
    ASSERT_EQ(decoded, actual);
}
INSTANTIATE_TEST_SUITE_P(bip32, Bip39VectorTesting_B, testing::ValuesIn(t39::VectorData));

class Bip32VectorTesting1 : public ::testing::TestWithParam<t32::Data> {};
TEST_P(Bip32VectorTesting1, derivepriv) {
    auto data = GetParam();
    auto raw = btcpp::utils::from_hex(seed1);

    auto master_key = btcpp::utils::from_short_seed(raw);
    auto hdkey = b32::tohdkey(master_key, b32::Network::MAINNET);
    auto derived = b32::deriveprv(hdkey, data.chain);
    auto serial = b32::serialize(derived);
    std::string actual = b58::encodecheck(serial);

    auto expected = b58::decodecheck(data.extprv);
    std::cout << "prvexpect: " << btcpp::utils::to_hex(expected) << std::endl;
    std::cout << "prvactual: " << btcpp::utils::to_hex(serial) << std::endl;

    ASSERT_STREQ(data.extprv.c_str(), actual.c_str());
}
TEST_P(Bip32VectorTesting1, derivepub) {
    auto data = GetParam();
    auto raw = btcpp::utils::from_hex(seed1);

    auto master_key = btcpp::utils::from_short_seed(raw);
    auto hdkey = b32::tohdkey(master_key, b32::Network::MAINNET);
    auto derived = b32::derivepub(hdkey, data.chain);
    auto serial = b32::serialize(derived);

    auto expected = b58::decodecheck(data.extpub);
    std::cout << "pubexpect: " << btcpp::utils::to_hex(expected) << std::endl;
    std::cout << "pubactual: " << btcpp::utils::to_hex(serial) << std::endl;

    std::string actual = b58::encodecheck(serial);
    ASSERT_STREQ(data.extpub.c_str(), actual.c_str());
}
INSTANTIATE_TEST_SUITE_P(bip32, Bip32VectorTesting1, testing::ValuesIn(t32::VectorData1));
} // namespace test::bip32
