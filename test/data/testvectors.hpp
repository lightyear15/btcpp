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

namespace base58 {
struct Data {
    std::string hex;
    std::string base58;
};
extern const std::vector<Data> VectorData;
extern const std::vector<Data> VectorData2;
extern const std::vector<std::string> InvalidData;
} // namespace base58

namespace bip32 {
struct Data {
    std::string chain;
    std::string extpub;
    std::string extprv;
};
const std::string seed1 = "000102030405060708090a0b0c0d0e0f";
extern const std::vector<Data> VectorData1;
const std::string seed2 =
    "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
extern const std::vector<Data> VectorData2;

const std::string seed3 =
    "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be";
extern const std::vector<Data> VectorData3;

const std::string seed4 = "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678";
extern const std::vector<Data> VectorData4;

struct InvalidData {
    std::string key;
    std::string errormsg;
};
extern const std::vector<InvalidData> vectorInvalidData;
} // namespace bip32
} // namespace test
