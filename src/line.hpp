#pragma once

#include "storage.hpp"

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace axon {

struct LandingRecord {
    std::int64_t n = 0;
    std::string root;
    std::string stack;
    std::string title;
    std::string principal;
    std::string intent;
    std::string route;
    std::vector<std::string> paths;
    std::vector<std::string> domains;
    std::int64_t created = 0;
    Json json = Json::object();
};

[[nodiscard]] std::string domainOf(std::string_view path);
[[nodiscard]] std::vector<std::string> domainsOfPaths(std::vector<std::string> const &paths);

class DomainLockManager {
public:
    std::shared_ptr<std::mutex> get(std::string const &domain);

    struct DomainGuard {
        std::vector<std::shared_ptr<std::mutex>> locks;
        std::vector<std::unique_lock<std::mutex>> held;
        ~DomainGuard() = default;
        DomainGuard() = default;
        DomainGuard(DomainGuard &&) = default;
        DomainGuard &operator=(DomainGuard &&) = default;
        DomainGuard(DomainGuard const &) = delete;
        DomainGuard &operator=(DomainGuard const &) = delete;
    };

    [[nodiscard]] DomainGuard lock(std::vector<std::string> domains);

private:
    std::mutex map_mutex_;
    std::unordered_map<std::string, std::shared_ptr<std::mutex>> locks_;
};

class Line {
public:
    explicit Line(std::string name, std::string initial_root = "");

    [[nodiscard]] std::string const &name() const {
        return name_;
    }
    [[nodiscard]] std::pair<std::int64_t, std::string> head() const;
    [[nodiscard]] std::string rootAt(std::int64_t n) const;
    [[nodiscard]] std::int64_t lastWriteOf(std::string_view key) const;
    [[nodiscard]] bool isStale(std::vector<std::string> const &reads, std::int64_t base_n) const;

    [[nodiscard]] DomainLockManager::DomainGuard lockDomains(std::vector<std::string> const &domains);
    void apply(LandingRecord rec);
    [[nodiscard]] std::vector<LandingRecord> records(std::int64_t from = 0, std::int64_t to = -1) const;
    [[nodiscard]] std::unordered_map<std::string, int> domainStats() const;
    [[nodiscard]] std::size_t size() const;
    [[nodiscard]] Json toJson() const;

private:
    std::string name_;
    mutable std::shared_mutex rw_mutex_;
    std::vector<LandingRecord> records_;
    std::vector<std::string> roots_;
    std::unordered_map<std::string, std::int64_t> last_write_;
    DomainLockManager domain_locks_;
};

} // namespace axon
