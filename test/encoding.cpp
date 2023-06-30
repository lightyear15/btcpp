
#include <gtest/gtest.h>

#include "encoding.hpp"
#include "utils.hpp"


#include "data/testvectors.hpp"

#include <span>


namespace t58 = test::base58;

namespace test::encoding {

// TEST(Base58Testing, decode_1) {
//     auto decoded = btcpp::base58::decode("2g");
//     auto hexed = btcpp::utils::to_hex(decoded);
//     EXPECT_EQ(hexed, "61");
// }
// TEST(Base58Testing, decode_2) {
//     auto decoded = btcpp::base58::decode("a3gV");
//     auto hexed = btcpp::utils::to_hex(decoded);
//     EXPECT_EQ(hexed, "626262");
// }
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
} // namespace test::encoding
