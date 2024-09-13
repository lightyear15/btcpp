#pragma once

#include <array>
#include <cstdint>
#include <span>

namespace btcpp::ec {
using SecretKey = std::array<uint8_t, 32>;
using SpanSecretKey = std::span<const uint8_t, 32>;
using PublicKey = std::array<uint8_t, 65>;
using SpanPublicKey = std::span<const uint8_t, 65>;
using CompressedPublicKey = std::array<uint8_t, 33>;
using SpanCompressedPublicKey = std::span<const uint8_t, 33>;

CompressedPublicKey get_public_key(SpanSecretKey secret);
/*void to_address(const SpanPublicKey &public_key);*/

} // namespace btcpp::ec
