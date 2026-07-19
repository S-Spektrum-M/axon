#include "storage.hpp"

#include "symbols.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <list>
#include <llvm-c/blake3.h>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <set>
#include <stdexcept>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <utility>

namespace axon {
namespace {
void require(bool ok, std::string_view message) {
    if (!ok)
        throw std::runtime_error(std::string(message));
}
void writeAll(int fd, std::string_view bytes) {
    while (!bytes.empty()) {
        auto n = ::write(fd, bytes.data(), bytes.size());
        if (n < 0 && errno == EINTR)
            continue;
        require(n > 0, "write failed");
        bytes.remove_prefix(static_cast<std::size_t>(n));
    }
}
void syncDirectory(Path const &path) {
    Descriptor fd(::open(path.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    require(::fsync(fd.get()) == 0, "directory fsync failed");
}
using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using Context = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
Key privateKey(std::string_view seed) {
    auto raw = axon::unhex(seed);
    require(raw.size() == 32, "Ed25519 seed must contain 32 bytes");
    Key key(EVP_PKEY_new_raw_private_key(
                EVP_PKEY_ED25519, nullptr, reinterpret_cast<unsigned char const *>(raw.data()), raw.size()),
            EVP_PKEY_free);
    require(bool(key), "Ed25519 key creation failed");
    return key;
}
constexpr std::size_t MIN_CHUNK = 2048;
constexpr std::size_t AVG_CHUNK = 8192;
constexpr std::size_t MAX_CHUNK = 65536;
std::array<std::uint64_t, 256> gearTable() {
    std::array<std::uint64_t, 256> table{};
    std::uint64_t x = 0x6c65646765720001;
    for (auto &entry : table) {
        x += 0x9e3779b97f4a7c15;
        auto z = x;
        z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9;
        z = (z ^ (z >> 27)) * 0x94d049bb133111eb;
        entry = z ^ (z >> 31);
    }
    return table;
}
std::size_t cut(std::string_view data) {
    static auto const GEAR = gearTable();
    auto n = std::min(data.size(), MAX_CHUNK);
    if (n <= MIN_CHUNK)
        return n;
    std::uint64_t fingerprint = 0;
    for (auto i = MIN_CHUNK; i < n; ++i) {
        fingerprint = (fingerprint << 1) + GEAR[static_cast<unsigned char>(data[i])];
        auto mask = i < AVG_CHUNK ? 0x0003590703530000ULL : 0x0000d90003530000ULL;
        if ((fingerprint & mask) == 0)
            return i;
    }
    return n;
}
} // namespace
Descriptor::Descriptor(int fd) : fd_(fd) {
    require(fd >= 0, std::string("open: ") + std::strerror(errno));
}
Descriptor::~Descriptor() {
    ::close(fd_);
}
int Descriptor::get() const {
    return fd_;
}
std::string readFile(Path const &path) {
    std::ifstream stream(path, std::ios::binary);
    require(bool(stream), "cannot read " + path.string());
    std::string data(std::istreambuf_iterator<char>(stream), {});
    require(!stream.bad(), "read failed: " + path.string());
    return data;
}
void writeFile(Path const &path, std::string_view data, unsigned mode) {
    auto parent = path.parent_path().empty() ? Path(".") : path.parent_path();
    std::filesystem::create_directories(parent);
    auto temporary = Path(path.string() + ".tmp-" + axon::randomHex());
    try {
        Descriptor fd(::open(temporary.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode));
        writeAll(fd.get(), data);
        require(::fsync(fd.get()) == 0, "fsync failed: " + temporary.string());
        std::filesystem::rename(temporary, path);
        syncDirectory(parent);
    } catch (...) {
        std::error_code ignored;
        std::filesystem::remove(temporary, ignored);
        throw;
    }
}
std::string hex(std::string_view bytes) {
    constexpr std::string_view DIGITS = "0123456789abcdef";
    std::string result;
    result.reserve(bytes.size() * 2);
    for (unsigned char byte : bytes) {
        result += DIGITS[byte >> 4];
        result += DIGITS[byte & 15];
    }
    return result;
}
std::string unhex(std::string_view text) {
    require(text.size() % 2 == 0, "invalid hex length");
    auto digit = [](char c) -> unsigned {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        throw std::runtime_error("invalid hexadecimal data");
    };
    std::string result;
    for (std::size_t i = 0; i < text.size(); i += 2)
        result += static_cast<char>((digit(text[i]) << 4) | digit(text[i + 1]));
    return result;
}
std::string hash(std::string_view bytes) {
    llvm_blake3_hasher hasher;
    llvm_blake3_hasher_init(&hasher);
    llvm_blake3_hasher_update(&hasher, bytes.data(), bytes.size());
    std::array<unsigned char, 32> digest{};
    llvm_blake3_hasher_finalize(&hasher, digest.data(), digest.size());
    return axon::hex(std::string_view(reinterpret_cast<char const *>(digest.data()), digest.size()));
}
std::string randomHex(std::size_t bytes) {
    require(bytes <= 1024, "random request too large");
    std::string raw(bytes, '\0');
    require(RAND_bytes(reinterpret_cast<unsigned char *>(raw.data()), static_cast<int>(raw.size())) == 1,
            "secure random generator failed");
    return axon::hex(raw);
}
std::int64_t now() {
    return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}
std::string cleanPath(std::string_view path, bool allow_root) {
    require(path.find('\0') == std::string_view::npos && path.find('\\') == std::string_view::npos,
            "invalid repository path");
    require(!path.starts_with('/'), "repository paths must be relative");
    auto normalized = Path(path).lexically_normal();
    for (auto const &part : normalized)
        require(part != "..", "path escapes repository");
    auto result = normalized.generic_string();
    while (result.ends_with('/'))
        result.pop_back();
    if (result == ".")
        result.clear();
    require(allow_root || !result.empty(), "empty path");
    require(!result.starts_with(".axon/") && result != ".axon", "reserved path");
    return result;
}
std::string publicKey(std::string_view seed) {
    auto key = privateKey(seed);
    std::string raw(32, '\0');
    auto size = raw.size();
    require(EVP_PKEY_get_raw_public_key(key.get(), reinterpret_cast<unsigned char *>(raw.data()), &size) == 1,
            "public key extraction failed");
    return axon::hex(raw);
}
std::string sign(std::string_view seed, std::string_view message) {
    auto key = privateKey(seed);
    Context context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    require(bool(context) && EVP_DigestSignInit(context.get(), nullptr, nullptr, nullptr, key.get()) == 1,
            "signature initialization failed");
    std::string signature(64, '\0');
    auto size = signature.size();
    require(EVP_DigestSign(context.get(),
                           reinterpret_cast<unsigned char *>(signature.data()),
                           &size,
                           reinterpret_cast<unsigned char const *>(message.data()),
                           message.size()) == 1,
            "signature failed");
    return axon::hex(signature);
}
bool verify(std::string_view key, std::string_view message, std::string_view signature) {
    auto raw = axon::unhex(key);
    auto sig = axon::unhex(signature);
    if (raw.size() != 32 || sig.size() != 64)
        return false;
    Key public_key(EVP_PKEY_new_raw_public_key(
                       EVP_PKEY_ED25519, nullptr, reinterpret_cast<unsigned char const *>(raw.data()), raw.size()),
                   EVP_PKEY_free);
    Context context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
    return public_key && context &&
           EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, public_key.get()) == 1 &&
           EVP_DigestVerify(context.get(),
                            reinterpret_cast<unsigned char const *>(sig.data()),
                            sig.size(),
                            reinterpret_cast<unsigned char const *>(message.data()),
                            message.size()) == 1;
}
Path configDirectory() {
    auto override_dir = std::getenv("AXON_HOME");
    if (override_dir && *override_dir)
        return Path(override_dir);
    auto xdg = std::getenv("XDG_CONFIG_HOME");
    if (xdg && *xdg)
        return Path(xdg) / "axon";
    auto home = std::getenv("HOME");
    return Path(home ? home : ".") / ".config" / "axon";
}
struct Store::Cache {
    struct Entry {
        std::string bytes;
        Json parsed;
        struct stat stamp{};
        std::size_t weight;
        std::list<std::string>::iterator position;
    };
    std::mutex mutex;
    std::unordered_map<std::string, Entry> entries;
    std::list<std::string> recency;
    std::size_t weight = 0;
    static constexpr std::size_t MAX_WEIGHT = 32 * 1024 * 1024;
    static constexpr std::size_t MAX_ENTRIES = 4096;
    static bool unchanged(struct stat const &before, struct stat const &after) {
        return before.st_dev == after.st_dev && before.st_ino == after.st_ino && before.st_size == after.st_size &&
               before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec &&
               before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec;
    }
    void trim() {
        while (!entries.empty() && (entries.size() > MAX_ENTRIES || weight > MAX_WEIGHT)) {
            auto oldest = entries.find(recency.back());
            weight -= oldest->second.weight;
            entries.erase(oldest);
            recency.pop_back();
        }
    }
};
Store::Store(Path const &directory) : cache_(std::make_shared<Cache>()), directory_(directory / "cas") {
    std::filesystem::create_directories(directory_);
}
bool Store::has(std::string_view id) const {
    if (id.size() != 64 || id.find_first_not_of("0123456789abcdef") != std::string_view::npos)
        return false;
    return std::filesystem::exists(directory_ / std::string(id.substr(0, 2)) / std::string(id.substr(2)));
}
Path Store::directory() const {
    return directory_;
}
std::string Store::put(std::string_view data) {
    auto id = axon::hash(data);
    auto path = directory_ / id.substr(0, 2) / id.substr(2);
    if (!std::filesystem::exists(path))
        axon::writeFile(path, data);
    return id;
}
std::string Store::get(std::string_view id) const {
    require(id.size() == 64 && id.find_first_not_of("0123456789abcdef") == std::string_view::npos,
            "invalid object hash");
    auto key = std::string(id);
    auto path = directory_ / key.substr(0, 2) / key.substr(2);
    struct stat stamp{};
    require(::stat(path.c_str(), &stamp) == 0, "missing CAS object " + key);
    {
        std::lock_guard lock(cache_->mutex);
        auto cached = cache_->entries.find(key);
        if (cached != cache_->entries.end()) {
            if (Cache::unchanged(cached->second.stamp, stamp)) {
                cache_->recency.splice(cache_->recency.begin(), cache_->recency, cached->second.position);
                return cached->second.bytes;
            }
            cache_->weight -= cached->second.weight;
            cache_->recency.erase(cached->second.position);
            cache_->entries.erase(cached);
        }
    }
    auto bytes = axon::readFile(path);
    require(axon::hash(bytes) == id, "corrupt CAS object " + key);
    if (bytes.size() <= Cache::MAX_WEIGHT) {
        std::lock_guard lock(cache_->mutex);
        if (!cache_->entries.contains(key)) {
            cache_->recency.push_front(key);
            cache_->entries.emplace(key, Cache::Entry{bytes, nullptr, stamp, bytes.size(), cache_->recency.begin()});
            cache_->weight += bytes.size();
            cache_->trim();
        }
    }
    return bytes;
}
std::string Store::putBlob(std::string_view data) {
    Json chunks = Json::array();
    auto size = data.size();
    while (!data.empty()) {
        auto n = cut(data);
        chunks.push_back(put(data.substr(0, n)));
        data.remove_prefix(n);
    }
    return put(Json{{"type", "blob"}, {"size", size}, {"chunks", chunks}}.dump());
}
std::string Store::blob(std::string_view id) const {
    auto manifest = node(id);
    require(manifest.at("type") == "blob", "not a blob");
    std::string bytes;
    for (auto const &chunk : manifest.at("chunks"))
        bytes += get(chunk.get<std::string>());
    require(bytes.size() == manifest.at("size").get<std::size_t>(), "invalid blob size");
    return bytes;
}
Json Store::node(std::string_view id) const {
    auto bytes = get(id); // Validate the disk fingerprint even for parsed-node hits.
    auto key = std::string(id);
    {
        std::lock_guard lock(cache_->mutex);
        auto cached = cache_->entries.find(key);
        if (cached != cache_->entries.end() && !cached->second.parsed.is_null())
            return cached->second.parsed;
    }
    auto parsed = Json::parse(bytes);
    {
        std::lock_guard lock(cache_->mutex);
        auto cached = cache_->entries.find(key);
        if (cached != cache_->entries.end() && cached->second.parsed.is_null()) {
            cached->second.parsed = parsed;
            // Charge a conservative multiplier for JSON nodes and allocator overhead.
            auto cost = bytes.size() * 16;
            cached->second.weight += cost;
            cache_->weight += cost;
            cache_->trim();
        }
    }
    return parsed;
}
std::string Store::empty() {
    return put(Json::object().dump());
}
namespace {
int nibbleAt(std::string_view name, std::size_t depth) {
    if (depth >= 64)
        return 0;
    auto h = axon::hash(name);
    char c = h[depth];
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return 0;
}
bool isDirShard(Json const &n) {
    return n.is_object() && n.value("type", "") == "dir_shard" && n.contains("shards") && n.at("shards").is_array();
}
} // namespace
Json Store::dirGet(std::string_view dir_root, std::string_view name, std::size_t depth) const {
    auto n = node(dir_root);
    if (!isDirShard(n)) {
        if (n.contains(std::string(name)))
            return n.at(std::string(name));
        return nullptr;
    }
    auto idx = static_cast<std::size_t>(nibbleAt(name, depth));
    auto const &shards = n.at("shards");
    if (idx >= shards.size())
        return nullptr;
    auto sh = shards.at(idx).get<std::string>();
    if (sh.empty())
        return nullptr;
    return dirGet(sh, name, depth + 1);
}
void Store::dirCollect(std::string_view dir_root, Json &out) const {
    auto n = node(dir_root);
    if (!isDirShard(n)) {
        for (auto const &[name, val] : n.items())
            out[name] = val;
        return;
    }
    for (auto const &sh : n.at("shards")) {
        auto h = sh.get<std::string>();
        if (!h.empty())
            dirCollect(h, out);
    }
}
std::size_t Store::dirCount(std::string_view dir_root) const {
    auto n = node(dir_root);
    if (!isDirShard(n))
        return n.size();
    return n.at("count").get<std::size_t>();
}
std::string Store::dirBuild(Json const &entries, std::size_t depth) {
    if (entries.size() <= shard_max_ || depth >= 63)
        return put(entries.dump());
    std::array<Json, 16> parts;
    for (int i = 0; i < 16; ++i)
        parts[i] = Json::object();
    for (auto const &[name, val] : entries.items()) {
        auto idx = nibbleAt(name, depth);
        parts[static_cast<std::size_t>(idx)][name] = val;
    }
    Json shards = Json::array();
    for (int i = 0; i < 16; ++i) {
        if (parts[i].empty())
            shards.push_back("");
        else
            shards.push_back(dirBuild(parts[i], depth + 1));
    }
    Json shard_node{{"type", "dir_shard"}, {"count", entries.size()}, {"shards", shards}};
    return put(shard_node.dump());
}
std::string Store::dirSet(std::string_view dir_root, std::string_view name, Json const &entry, std::size_t depth) {
    auto n = node(dir_root);
    if (!isDirShard(n)) {
        auto entries = n;
        if (entry.is_null())
            entries.erase(std::string(name));
        else
            entries[std::string(name)] = entry;
        if (entries.empty())
            return empty();
        if (entries.size() <= shard_max_ || depth >= 63)
            return put(entries.dump());
        return dirBuild(entries, depth);
    }
    auto idx = static_cast<std::size_t>(nibbleAt(name, depth));
    auto shards = n.at("shards");
    auto child_hash = shards.at(idx).get<std::string>();
    if (child_hash.empty())
        child_hash = empty();
    auto new_child = dirSet(child_hash, name, entry, depth + 1);
    if (new_child == empty())
        shards[idx] = "";
    else
        shards[idx] = new_child;
    std::size_t total = 0;
    for (auto const &sh : shards) {
        auto h = sh.get<std::string>();
        if (!h.empty())
            total += dirCount(h);
    }
    if (total == 0)
        return empty();
    if (total <= shard_max_) {
        Json all = Json::object();
        for (auto const &sh : shards) {
            auto h = sh.get<std::string>();
            if (!h.empty())
                dirCollect(h, all);
        }
        return dirBuild(all, depth);
    }
    Json shard_node{{"type", "dir_shard"}, {"count", total}, {"shards", shards}};
    return put(shard_node.dump());
}
Json Store::lookup(std::string_view root, std::string_view path) const {
    if (path.empty())
        return Json{{"kind", "dir"}, {"hash", root}};
    auto split = path.find('/');
    auto name = path.substr(0, split);
    auto entry = dirGet(root, name, 0);
    if (entry.is_null())
        return nullptr;
    if (split == std::string_view::npos)
        return entry;
    if (entry.at("kind") != "dir")
        return nullptr;
    return lookup(entry.at("hash").get<std::string>(), path.substr(split + 1));
}
Json Store::list(std::string_view root, std::string_view path) const {
    auto entry = lookup(root, path);
    require(!entry.is_null() && entry.at("kind") == "dir", "not a directory: " + std::string(path));
    Json result = Json::object();
    dirCollect(entry.at("hash").get<std::string>(), result);
    return result;
}
std::string Store::set(std::string_view root, std::string_view path, Json const &entry) {
    require(!path.empty(), "cannot replace tree root");
    auto split = path.find('/');
    auto name = path.substr(0, split);
    if (split == std::string_view::npos) {
        return dirSet(root, name, entry, 0);
    }
    auto subroot = empty();
    auto cur = dirGet(root, name, 0);
    if (!cur.is_null()) {
        require(cur.at("kind") == "dir", "file is in the way: " + std::string(name));
        subroot = cur.at("hash").get<std::string>();
    }
    auto next = set(subroot, path.substr(split + 1), entry);
    Json dir_entry = (next == empty() && !(cur.is_object() && cur.value("explicit", false)))
                         ? Json(nullptr)
                         : Json{{"kind", "dir"}, {"hash", next}};
    if (!cur.is_null() && cur.value("explicit", false))
        dir_entry["explicit"] = true;
    return dirSet(root, name, dir_entry, 0);
}
Json Store::files(std::string_view root, std::string_view prefix) const {
    Json result = Json::object();
    Json entries = Json::object();
    dirCollect(root, entries);
    for (auto const &[name, entry] : entries.items()) {
        auto path = std::string(prefix) + name;
        if (entry.at("kind") == "dir")
            result.update(files(entry.at("hash").get<std::string>(), path + "/"));
        else
            result[path] = entry;
    }
    return result;
}
Json Store::diff(std::string_view before, std::string_view after) const {
    Json result = Json::array();
    if (before == after)
        return result;
    auto a = files(before);
    auto b = files(after);
    std::set<std::string> paths;
    for (auto const &[path, entry] : a.items()) {
        (void)entry;
        paths.insert(path);
    }
    for (auto const &[path, entry] : b.items()) {
        (void)entry;
        paths.insert(path);
    }
    for (auto const &path : paths) {
        auto old = a.value(path, Json());
        auto next = b.value(path, Json());
        if (old != next)
            result.push_back({{"path", path}, {"old", old}, {"new", next}});
    }
    return result;
}
std::string Store::readHash(std::string_view root, std::string_view key) const {
    if (key.starts_with("symbol:")) {
        auto split = key.find('#', 7);
        if (split == std::string_view::npos)
            throw std::runtime_error("invalid symbol read key");
        auto entry = lookup(root, key.substr(7, split - 7));
        if (entry.is_null() || entry.at("kind") != "file")
            return "";
        auto source = blob(entry.at("hash").get<std::string>());
        try {
            return readSymbol(source, key.substr(split + 1)).at("hash").get<std::string>();
        } catch (std::exception const &) {
            return "unparseable:" + entry.at("hash").get<std::string>();
        }
    }
    if (key == "**")
        return std::string(root);
    if (key.empty() || key.ends_with('/')) {
        auto path = key.empty() ? key : key.substr(0, key.size() - 1);
        auto entry = lookup(root, path);
        if (entry.is_null() || entry.at("kind") != "dir")
            return "";
        Json names = Json::array();
        for (auto const &[name, value] : list(root, path).items()) {
            (void)value;
            names.push_back(name);
        }
        return axon::hash(names.dump());
    }
    return axon::hash(lookup(root, key).dump());
}
Database::Database(Path const &directory, bool no_sync)
    : journal_(directory / "journal.jsonl"),
      lock_((std::filesystem::create_directories(directory),
             ::open((directory / "LOCK").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600))),
      no_sync_(no_sync) {
    require(::flock(lock_.get(), LOCK_EX | LOCK_NB) == 0, "repository is already open by another process");
    if (!std::filesystem::exists(journal_))
        return;
    auto data = axon::readFile(journal_);
    std::size_t start = 0;
    while (start < data.size()) {
        auto end = data.find('\n', start);
        if (end == std::string::npos) {
            std::filesystem::resize_file(journal_, start);
            break;
        }
        auto record = Json::parse(data.substr(start, end - start));
        auto patch = record.at("patch");
        require(record.at("hash") == axon::hash(patch.dump()), "journal checksum mismatch");
        state_ = state_.patch(patch);
        start = end + 1;
    }
    tip_ = state_;
}
Database::~Database() = default;
Json Database::state() const {
    std::lock_guard lk(state_mutex_);
    return state_.json();
}
Json Database::read(std::function<Json(Json const &)> const &select) const {
    std::lock_guard lock(state_mutex_);
    return select(state_.json());
}
StateTransaction Database::transaction() const {
    std::lock_guard lock(state_mutex_);
    return StateTransaction(state_);
}
bool Database::commit(StateTransaction const &transaction) {
    std::unique_lock batch(batch_mutex_);
    if (!transaction.valid(tip_))
        return false;
    enqueue(batch, transaction.changes(tip_));
    return true;
}
void Database::commit(Json const &next) {
    std::unique_lock batch(batch_mutex_);
    enqueue(batch, Json::diff(tip_.json(), next));
}
void Database::commitPatch(Json const &patch) {
    std::unique_lock batch(batch_mutex_);
    enqueue(batch, patch);
}
void Database::compact() {
    std::unique_lock batch(batch_mutex_);
    idle_.wait(batch, [this] { return !flusher_active_; });
    require(damaged_.empty(), damaged_);
    // Replace the journal atomically with a single checkpoint transaction.
    // A crash sees either the complete old history or this complete snapshot.
    Json patch = Json::array({{{"op", "replace"}, {"path", ""}, {"value", tip_.json()}}});
    axon::writeFile(journal_, Json{{"patch", patch}, {"hash", axon::hash(patch.dump())}}.dump() + "\n");
}
void Database::enqueue(std::unique_lock<std::mutex> &batch, Json patch) {
    require(damaged_.empty(), damaged_);
    if (patch.empty())
        return;
    tip_ = tip_.patch(patch);
    auto waiter = std::make_shared<Waiter>();
    pending_records_.push_back(Json{{"patch", patch}, {"hash", axon::hash(patch.dump())}}.dump() + "\n");
    pending_states_.push_back(tip_);
    pending_waiters_.push_back(waiter);
    if (flusher_active_) {
        waiter->cv.wait(batch, [&waiter] { return waiter->done; });
        require(waiter->error.empty(), waiter->error);
        return;
    }
    // This commit leads: flush batches until none are queued.
    flusher_active_ = true;
    while (!pending_records_.empty()) {
        auto records = std::exchange(pending_records_, {});
        auto states = std::exchange(pending_states_, {});
        auto waiters = std::exchange(pending_waiters_, {});
        batch.unlock();
        bool damaged = false;
        auto error = flush(records, damaged);
        batch.lock();
        if (error.empty()) {
            std::lock_guard lk(state_mutex_);
            state_ = std::move(states.back());
        } else {
            // Commits queued during the flush were diffed against the failed patches.
            for (auto &queued : pending_waiters_)
                waiters.push_back(std::move(queued));
            pending_records_.clear();
            pending_states_.clear();
            pending_waiters_.clear();
            if (damaged)
                damaged_ = error;
            std::lock_guard lk(state_mutex_);
            tip_ = state_;
        }
        for (auto const &done : waiters) {
            done->error = error;
            done->done = true;
            done->cv.notify_one();
        }
    }
    flusher_active_ = false;
    idle_.notify_all();
    require(waiter->error.empty(), waiter->error);
}
std::string Database::flush(std::vector<std::string> const &records, bool &damaged) {
    std::string bytes;
    for (auto const &record : records)
        bytes += record;
    try {
        Descriptor fd(::open(journal_.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600));
        struct stat before{};
        require(::fstat(fd.get(), &before) == 0, "journal stat failed");
        try {
            writeAll(fd.get(), bytes);
            if (!no_sync_) {
                require(::fsync(fd.get()) == 0, "journal fsync failed");
                syncDirectory(journal_.parent_path());
            }
            return "";
        } catch (std::exception const &error) {
            // Cut off partial records so the journal never keeps a commit its caller saw fail.
            if (::ftruncate(fd.get(), before.st_size) == 0 && (no_sync_ || ::fsync(fd.get()) == 0))
                return error.what();
            damaged = true;
            return std::string(error.what()) + "; journal truncation failed, reopen the repository to recover";
        }
    } catch (std::exception const &error) {
        return error.what();
    }
}
} // namespace axon
