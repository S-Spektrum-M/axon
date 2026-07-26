#pragma once
#include "storage.hpp"

namespace axon {
[[nodiscard]] Json filesystemRequest(Store &store, Json &workspace, Json const &request);
} // namespace axon
