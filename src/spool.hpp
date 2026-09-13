#pragma once
#include "storage.hpp"

namespace axon {
// The spool is bound to a server and principal. Replay removes an entry only
// after the server acknowledges its durable, idempotent operation ID.
[[nodiscard]] Json spoolEdit(Json request, Json const &config);
[[nodiscard]] Json replayEdits(Json const &config, std::string_view seed);
} // namespace axon
