#pragma once
#include "storage.hpp"

namespace axon {
// Retains stable sequence numbers and pins bases of live workspaces/stacks.
[[nodiscard]] Json pruneMetadata(StateTransaction &state, std::int64_t cutoff, std::size_t keep, bool dry_run);
} // namespace axon
