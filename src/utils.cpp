
#include "utils.hpp"

#include <boost/algorithm/hex.hpp>

namespace btcpp::utils {

std::string to_hex(std::span<uint8_t> in) noexcept {
    std::string out;
    boost::algorithm::hex_lower(std::cbegin(in), std::cend(in), std::back_inserter(out));
    return out;
}

std::vector<uint8_t> from_hex(std::string_view in) {
    std::vector<uint8_t> out;
    out.reserve(in.size() / 2);
    boost::algorithm::unhex(std::cbegin(in), std::cend(in), std::back_inserter(out));
    return out;
}

} // namespace btcpp::utils
