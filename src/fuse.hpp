#pragma once
#include "storage.hpp"

#include <functional>
#include <map>

namespace axon {
// Linux FUSE protocol adapter; the injectable RPC boundary permits protocol
// tests without /dev/fuse. No kernel attribute/data cache hides tracked reads.
class FuseSession {
public:
    explicit FuseSession(std::function<Json(Json)> rpc);
    [[nodiscard]] std::string dispatch(std::string_view packet);

private:
    [[nodiscard]] std::uint64_t inode(std::string const &path);
    [[nodiscard]] Json call(std::string_view action, std::string const &path, Json extra = Json::object());
    std::function<Json(Json)> rpc_;
    std::map<std::uint64_t, std::string> paths_{{1, ""}};
    std::map<std::string, std::uint64_t> inodes_{{"", 1}};
    struct Metadata {
        std::string fingerprint;
        std::uint64_t atime = 0;
        std::uint64_t mtime = 0;
    };
    std::map<std::string, Metadata> metadata_;
    std::uint64_t next_ = 2;
};
void mountWorkspace(std::string_view workspace, Path const &mountpoint, Json const &config, std::string_view seed);
} // namespace axon
