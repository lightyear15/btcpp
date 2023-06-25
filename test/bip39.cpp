
#include <cstddef>
#include <iostream>

#include <boost/algorithm/hex.hpp>
#include <gtest/gtest.h>

#include "bip39.hpp"
#include "bip39/dictionary.hpp"
#include "utils.hpp"

#include "data/bip39_testvector.hpp"

using namespace btc::bip39;
using namespace test::bip39;

TEST(bip39, generate_entropy) {
    auto output1 = generate<Entropy128>();
    auto output2 = generate<Entropy128>();
    ASSERT_EQ(output1.size(), 16);
    ASSERT_EQ(output2.size(), 16);
    ASSERT_NE(output1, output2);
}

class Bip39VectorTesting : public ::testing::TestWithParam<Data>{};
TEST_P(Bip39VectorTesting, to_words) {
    auto data = GetParam();
    auto entropy = btc::utils::from_hex(data.entropy);
    auto words = details::to_mnemonic(english::dictionary, entropy);
    ASSERT_EQ(words, data.mnemonic);
}
TEST_P(Bip39VectorTesting, to_seed) {
    auto data = GetParam();
    auto seed = to_seed(data.mnemonic, "TREZOR");
    ASSERT_EQ(btc::utils::to_hex(seed), data.seed);
}
INSTANTIATE_TEST_SUITE_P(bip39, Bip39VectorTesting, testing::ValuesIn(VectorData));
