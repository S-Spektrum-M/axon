#pragma once
#include "storage.hpp"

#include <functional>

namespace axon {
// Read-only browser view. The local proxy signs allowlisted snapshot/stack reads
// with the CLI identity; it never forwards workspace reads, which mutate read sets.
[[nodiscard]] Json webRequest(Json const &call, std::function<Json(Json)> const &rpc);
void serveWeb(Json const &config, std::string_view seed, std::string_view address);
} // namespace axon
