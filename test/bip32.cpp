
#include <gtest/gtest-matchers.h>
#include <gtest/gtest.h>

#include <gtest/internal/gtest-param-util.h>
#include <iostream>
#include <stdexcept>

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

    ASSERT_STREQ(data.extprv.c_str(), actual.c_str());
}
TEST_P(Bip32VectorTesting1, derivepub) {
    auto data = GetParam();
    auto raw = btcpp::utils::from_hex(seed1);

    auto master_key = btcpp::utils::from_short_seed(raw);
    auto hdkey = b32::tohdkey(master_key, b32::Network::MAINNET);
    auto derived = b32::derivepub(hdkey, data.chain);
    auto serial = b32::serialize(derived);

    std::string actual = b58::encodecheck(serial);
    ASSERT_STREQ(data.extpub.c_str(), actual.c_str());
}
INSTANTIATE_TEST_SUITE_P(bip32, Bip32VectorTesting1, testing::ValuesIn(t32::VectorData1));

class Bip32VectorTesting2 : public ::testing::TestWithParam<t32::Data> {};
TEST_P(Bip32VectorTesting2, derivepriv) {
    auto data = GetParam();
    auto raw = btcpp::utils::from_hex(seed2);

    auto master_key = btcpp::utils::from_short_seed(raw);
    auto hdkey = b32::tohdkey(master_key, b32::Network::MAINNET);
    auto derived = b32::deriveprv(hdkey, data.chain);
    auto serial = b32::serialize(derived);
    std::string actual = b58::encodecheck(serial);

    ASSERT_STREQ(data.extprv.c_str(), actual.c_str());
}
TEST_P(Bip32VectorTesting2, derivepub) {
    auto data = GetParam();
    auto raw = btcpp::utils::from_hex(seed2);

    auto master_key = btcpp::utils::from_short_seed(raw);
    auto hdkey = b32::tohdkey(master_key, b32::Network::MAINNET);
    auto derived = b32::derivepub(hdkey, data.chain);
    auto serial = b32::serialize(derived);

    std::string actual = b58::encodecheck(serial);
    ASSERT_STREQ(data.extpub.c_str(), actual.c_str());
}
INSTANTIATE_TEST_SUITE_P(bip32, Bip32VectorTesting2, testing::ValuesIn(t32::VectorData2));

class Bip32VectorTesting3 : public ::testing::TestWithParam<t32::Data> {};
TEST_P(Bip32VectorTesting3, derivepriv) {
    auto data = GetParam();
    auto raw = btcpp::utils::from_hex(seed3);

    auto master_key = btcpp::utils::from_short_seed(raw);
    auto hdkey = b32::tohdkey(master_key, b32::Network::MAINNET);
    auto derived = b32::deriveprv(hdkey, data.chain);
    auto serial = b32::serialize(derived);
    std::string actual = b58::encodecheck(serial);

    ASSERT_STREQ(data.extprv.c_str(), actual.c_str());
}
TEST_P(Bip32VectorTesting3, derivepub) {
    auto data = GetParam();
    auto raw = btcpp::utils::from_hex(seed3);

    auto master_key = btcpp::utils::from_short_seed(raw);
    auto hdkey = b32::tohdkey(master_key, b32::Network::MAINNET);
    auto derived = b32::derivepub(hdkey, data.chain);
    auto serial = b32::serialize(derived);

    std::string actual = b58::encodecheck(serial);
    ASSERT_STREQ(data.extpub.c_str(), actual.c_str());
}
INSTANTIATE_TEST_SUITE_P(bip32, Bip32VectorTesting3, testing::ValuesIn(t32::VectorData3));

class Bip32VectorTesting4 : public ::testing::TestWithParam<t32::Data> {};
TEST_P(Bip32VectorTesting4, derivepriv) {
    auto data = GetParam();
    auto raw = btcpp::utils::from_hex(seed4);

    auto master_key = btcpp::utils::from_short_seed(raw);
    auto hdkey = b32::tohdkey(master_key, b32::Network::MAINNET);
    auto derived = b32::deriveprv(hdkey, data.chain);
    auto serial = b32::serialize(derived);
    std::string actual = b58::encodecheck(serial);

    ASSERT_STREQ(data.extprv.c_str(), actual.c_str());
}
TEST_P(Bip32VectorTesting4, derivepub) {
    auto data = GetParam();
    auto raw = btcpp::utils::from_hex(seed4);

    auto master_key = btcpp::utils::from_short_seed(raw);
    auto hdkey = b32::tohdkey(master_key, b32::Network::MAINNET);
    auto derived = b32::derivepub(hdkey, data.chain);
    auto serial = b32::serialize(derived);

    std::string actual = b58::encodecheck(serial);
    ASSERT_STREQ(data.extpub.c_str(), actual.c_str());
}
INSTANTIATE_TEST_SUITE_P(bip32, Bip32VectorTesting4, testing::ValuesIn(t32::VectorData4));

class Bip32InvalidVectorTesting : public ::testing::TestWithParam<t32::InvalidData> {};
TEST_P(Bip32InvalidVectorTesting, check) {
    auto data = GetParam();
    auto undertest = [&]() {
        b32::Bip32Serial serial = b58::bip32::decode(data.key);
        auto hdkey = b32::deserialize(serial);
    };
    ASSERT_THROW(undertest(), std::invalid_argument);
    try {
        undertest();
    } catch (const std::invalid_argument &e) {
        ASSERT_STREQ(data.errormsg.c_str(), e.what());
    }
}
INSTANTIATE_TEST_SUITE_P(bip32, Bip32InvalidVectorTesting, testing::ValuesIn(t32::vectorInvalidData));
} // namespace test::bip32
