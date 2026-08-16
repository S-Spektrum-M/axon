#pragma once
#include "storage.hpp"

#include <optional>

namespace axon {
struct Declaration {
    std::string name;
    std::string identity;
    std::size_t begin = 0;
    std::size_t end = 0;
};
// Parse self-contained C++23 source with Clang. Unsupported/invalid source is
// rejected; callers must fall back to whole-file reads/text merging.
[[nodiscard]] std::optional<std::vector<Declaration>> declarations(std::string_view source);
[[nodiscard]] Json readSymbol(std::string_view source, std::string_view name);
[[nodiscard]] std::optional<std::string>
mergeDeclarations(std::string_view base, std::string_view ours, std::string_view theirs);
} // namespace axon
