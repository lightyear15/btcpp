
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace btcpp::utils {

std::string to_hex(std::span<uint8_t> input) noexcept;
std::vector<uint8_t> from_hex(std::string_view input);

} // namespace btcpp::utils
