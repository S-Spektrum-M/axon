#pragma once

#include "state.hpp"

#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace axon {
using Json = nlohmann::json;
using Path = std::filesystem::path;

// All helpers are private to the executable. I/O errors propagate to its request boundary.
[[nodiscard]] std::string readFile(Path const &path);
void writeFile(Path const &path, std::string_view data, unsigned mode = 0600);
[[nodiscard]] std::string hash(std::string_view bytes);
[[nodiscard]] std::string randomHex(std::size_t bytes = 16);
[[nodiscard]] std::string hex(std::string_view bytes);
[[nodiscard]] std::string unhex(std::string_view bytes);
[[nodiscard]] std::int64_t now();
[[nodiscard]] std::string cleanPath(std::string_view path, bool allow_root = false);
[[nodiscard]] Path configDirectory();
[[nodiscard]] std::string publicKey(std::string_view seed);
[[nodiscard]] std::string sign(std::string_view seed, std::string_view message);
[[nodiscard]] bool verify(std::string_view key, std::string_view message, std::string_view signature);

class Descriptor {
public:
    explicit Descriptor(int fd);
    ~Descriptor();
    Descriptor(Descriptor const &) = delete;
    Descriptor &operator=(Descriptor const &) = delete;
    Descriptor(Descriptor &&) = delete;
    Descriptor &operator=(Descriptor &&) = delete;
    [[nodiscard]] int get() const;

private:
    int fd_;
};

class Store {
public:
    explicit Store(Path const &directory);
    [[nodiscard]] bool has(std::string_view id) const;
    [[nodiscard]] std::string put(std::string_view data);
    [[nodiscard]] std::string get(std::string_view id) const;
    [[nodiscard]] std::string putBlob(std::string_view data);
    [[nodiscard]] std::string blob(std::string_view id) const;
    [[nodiscard]] Json node(std::string_view id) const;
    [[nodiscard]] std::string empty();
    [[nodiscard]] Json lookup(std::string_view root, std::string_view path) const;
    [[nodiscard]] Json list(std::string_view root, std::string_view path = "") const;
    [[nodiscard]] std::string set(std::string_view root, std::string_view path, Json const &entry);
    [[nodiscard]] Json files(std::string_view root, std::string_view prefix = "") const;
    [[nodiscard]] Json diff(std::string_view before, std::string_view after) const;
    [[nodiscard]] std::string readHash(std::string_view root, std::string_view key) const;
    [[nodiscard]] Path directory() const;
    void setShardMaxForTest(std::size_t max) {
        shard_max_ = max;
    }
    [[nodiscard]] std::size_t shardMax() const {
        return shard_max_;
    }

private:
    struct Cache;
    std::shared_ptr<Cache> cache_;
    Path directory_;
    std::size_t shard_max_ = 1024;
    [[nodiscard]] Json dirGet(std::string_view dir_root, std::string_view name, std::size_t depth) const;
    void dirCollect(std::string_view dir_root, Json &out) const;
    [[nodiscard]] std::size_t dirCount(std::string_view dir_root) const;
    [[nodiscard]] std::string dirBuild(Json const &entries, std::size_t depth);
    [[nodiscard]] std::string
    dirSet(std::string_view dir_root, std::string_view name, Json const &entry, std::size_t depth);
};

// One checksummed JSON-patch transaction per journal line with group commit. A process lock excludes
// concurrent writers; fsync completes before the in-memory state becomes visible. A failed append is
// truncated away, failing its batch and every commit queued on top of it; if the truncation itself
// fails, the database refuses further commits until it is reopened and recovered.
class Database {
public:
    explicit Database(Path const &directory, bool no_sync = false);
    ~Database();
    [[nodiscard]] Json state() const;
    [[nodiscard]] Json read(std::function<Json(Json const &)> const &select) const;
    [[nodiscard]] StateTransaction transaction() const;
    [[nodiscard]] bool commit(StateTransaction const &transaction);
    void commit(Json const &next);
    void commitPatch(Json const &patch);
    void compact();
    void setNoSync(bool no_sync) {
        no_sync_ = no_sync;
    }

private:
    struct Waiter {
        std::condition_variable cv;
        bool done = false;
        std::string error;
        Waiter() = default;
    };
    void enqueue(std::unique_lock<std::mutex> &batch, Json patch);
    [[nodiscard]] std::string flush(std::vector<std::string> const &records, bool &damaged);
    Path journal_;
    Descriptor lock_;
    // state_ is durable and visible; tip_ adds queued patches that are not yet durable.
    StateSnapshot state_;
    StateSnapshot tip_;
    mutable std::mutex state_mutex_;
    std::mutex batch_mutex_;
    std::condition_variable idle_;
    std::vector<std::string> pending_records_;
    std::vector<StateSnapshot> pending_states_;
    std::vector<std::shared_ptr<Waiter>> pending_waiters_;
    std::string damaged_;
    bool flusher_active_ = false;
    bool no_sync_ = false;
};
} // namespace axon
