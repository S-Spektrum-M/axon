#pragma once
#include "repository.hpp"

#include <functional>
#include <string_view>

namespace axon {
void serve(Repository &repository, std::string_view address, Path const &certificate = {}, Path const &key = {});
[[nodiscard]] std::string cachedBlob(std::string_view server, std::string_view id);
[[nodiscard]] Json remoteRequest(std::string_view server, Json const &envelope);
void streamRequest(std::string_view server, Json const &envelope, std::function<void(Json const &)> const &consume);
} // namespace axon
