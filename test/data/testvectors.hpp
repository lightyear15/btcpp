#pragma once

#include <string>
#include <vector>

namespace test {
namespace bip39 {
struct Data {
    std::string entropy;
    std::vector<std::string> mnemonic;
    std::string seed;
    std::string master_key;
};
extern const std::vector<Data> VectorData;

struct BitcoinBookData {
    std::string entropy;
    std::vector<std::string> mnemonic;
    std::string passphrase;
    std::string seed;
};
extern const std::vector<BitcoinBookData> VectorBitcoinBookData;
} // namespace bip39

namespace bip32 {
struct Data {
    std::string chain;
    std::string extpub;
    std::string extprv;
};
const std::string seed1 = "000102030405060708090a0b0c0d0e0f";
extern const std::vector<Data> VectorData1;
} // namespace bip32

namespace base58 {
struct Data {
    std::string hex;
    std::string base58;
};
extern const std::vector<Data> VectorData;
extern const std::vector<Data> VectorData2;
extern const std::vector<std::string> InvalidData;
} // namespace base58
} // namespace test
