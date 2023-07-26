
#include <gtest/gtest.h>

#include "encoding.hpp"
#include "utils.hpp"


#include "data/testvectors.hpp"

#include <span>


namespace t58 = test::base58;

namespace test::encoding {

class Base58VectorTesting: public ::testing::TestWithParam<t58::Data> {};
TEST_P(Base58VectorTesting, decode) {
    auto data = GetParam();
    auto decoded = btcpp::base58::decode(data.base58);
    auto hexed = btcpp::utils::to_hex(decoded);
    EXPECT_EQ(hexed, data.hex);
}
TEST_P(Base58VectorTesting, encode) {
    auto data = GetParam();
    auto binary = btcpp::utils::from_hex(data.hex);
    auto encoded = btcpp::base58::encode(std::span(binary));
    EXPECT_EQ(data.base58, encoded);
}
INSTANTIATE_TEST_SUITE_P(encoding, Base58VectorTesting, testing::ValuesIn(t58::VectorData));

class Base58CheckVectorTesting: public ::testing::TestWithParam<t58::Data> {};
TEST_P(Base58CheckVectorTesting, decode) {
    auto data = GetParam();
    auto [prefix, decoded] = btcpp::base58::decodecheck(data.base58);
    auto hexed = btcpp::utils::to_hex(decoded);
    EXPECT_EQ(hexed, data.hex);
}
TEST_P(Base58CheckVectorTesting, encode) {
    auto data = GetParam();
    auto binary = btcpp::utils::from_hex(data.hex);
    auto encoded = btcpp::base58::encodecheck(std::span(binary.begin() + 1, binary.end()), *binary.begin());
    EXPECT_EQ(data.base58, encoded);
}
INSTANTIATE_TEST_SUITE_P(encoding, Base58CheckVectorTesting, testing::ValuesIn(t58::VectorData2));

} // namespace test::encoding
