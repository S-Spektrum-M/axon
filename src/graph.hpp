#pragma once
#include "storage.hpp"

#include <set>
#include <span>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>

namespace axon {
struct ProcessResult {
    int status = 0;
    std::string output;
};
// Runs argv directly (no implicit shell), captures combined output, kills the
// process group on timeout, and always reaps the child.
[[nodiscard]] ProcessResult runProcess(std::span<std::string const> args,
                                       Path const &directory,
                                       std::string_view input = "",
                                       int timeout_seconds = 60,
                                       std::stop_token stop = {});
[[nodiscard]] bool matches(std::string_view pattern, std::string_view path);
[[nodiscard]] Json mergeFile(Store &store, Json const &base, Json const &ours, Json const &theirs);
[[nodiscard]] std::string unifiedDiff(Store const &store, Json const &changes);
void materialize(Store const &store, Json const &files, Path const &directory);

class Graph {
public:
    explicit Graph(Store const &store, std::string_view root, std::string_view query_engine = "");
    [[nodiscard]] Json const &targets() const;
    [[nodiscard]] Json closure(std::string_view target) const;
    [[nodiscard]] Json affected(Json const &paths) const;
    [[nodiscard]] std::size_t cacheWeight() const;

private:
    void collect(std::string_view label, std::set<std::string> &visiting, Json &files, Json &definitions) const;
    Store store_;
    std::string root_;
    Json files_;
    Json targets_ = Json::object();
};

class GraphCache {
public:
    static std::shared_ptr<Graph> get(Store const &store, std::string_view root, std::string_view query_engine = "");
    static void clear();
};
} // namespace axon
