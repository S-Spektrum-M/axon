#pragma once
#include "storage.hpp"

#include <span>
#include <string>
#include <string_view>
namespace axon {
[[nodiscard]] Json
gitBridge(std::span<std::string const> args, Json const &options, Json const &config, std::string_view seed);
} // namespace axon
