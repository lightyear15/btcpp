
#include <gtest/gtest.h>

#include "encoding.hpp"
#include "bip32.hpp"
#include "bip39.hpp"
#include "utils.hpp"

#include "data/testvectors.hpp"

namespace b39 = btcpp::bip39;
namespace b32 = btcpp::bip32;
namespace t39 = test::bip39;

namespace test::bip32 {
class Bip39VectorTesting_B : public ::testing::TestWithParam<t39::Data> {};
TEST_P(Bip39VectorTesting_B, to_master_key) {
    auto data = GetParam();
    auto seed = b39::to_seed(btcpp::utils::from_hex(data.seed));
    // b32::MasterKey master_key = btcpp::base58::decode(data.master_key);
}
INSTANTIATE_TEST_SUITE_P(bip32, Bip39VectorTesting_B, testing::ValuesIn(t39::VectorData));

} // namespace test::bip32
