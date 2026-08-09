#include "line.hpp"

#include <algorithm>
#include <set>

namespace axon {

std::string domainOf(std::string_view path) {
    if (path.starts_with("symbol:"))
        path.remove_prefix(7);
    if (path.empty() || path == "**")
        return "";
    while (path.starts_with('/'))
        path.remove_prefix(1);
    while (path.ends_with('/'))
        path.remove_suffix(1);
    auto hash_pos = path.find('#');
    if (hash_pos != std::string_view::npos)
        path = path.substr(0, hash_pos);
    auto split = path.find('/');
    if (split == std::string_view::npos)
        return std::string(path);
    return std::string(path.substr(0, split));
}

std::vector<std::string> domainsOfPaths(std::vector<std::string> const &paths) {
    std::set<std::string> unique;
    for (auto const &p : paths) {
        auto d = domainOf(p);
        if (!d.empty())
            unique.insert(d);
    }
    return std::vector<std::string>(unique.begin(), unique.end());
}

std::shared_ptr<std::mutex> DomainLockManager::get(std::string const &domain) {
    std::lock_guard lk(map_mutex_);
    auto it = locks_.find(domain);
    if (it != locks_.end())
        return it->second;
    auto m = std::make_shared<std::mutex>();
    locks_[domain] = m;
    return m;
}

DomainLockManager::DomainGuard DomainLockManager::lock(std::vector<std::string> domains) {
    std::sort(domains.begin(), domains.end());
    domains.erase(std::unique(domains.begin(), domains.end()), domains.end());

    DomainGuard guard;
    for (auto const &d : domains) {
        auto m = get(d);
        guard.locks.push_back(m);
        guard.held.emplace_back(*m);
    }
    return guard;
}

Line::Line(std::string name, std::string initial_root) : name_(std::move(name)) {
    roots_.push_back(std::move(initial_root));
}

std::pair<std::int64_t, std::string> Line::head() const {
    std::shared_lock lk(rw_mutex_);
    auto n = static_cast<std::int64_t>(records_.size());
    return {n, roots_.at(static_cast<std::size_t>(n))};
}

std::string Line::rootAt(std::int64_t n) const {
    std::shared_lock lk(rw_mutex_);
    if (n < 0 || static_cast<std::size_t>(n) >= roots_.size())
        return roots_.back();
    return roots_.at(static_cast<std::size_t>(n));
}

std::int64_t Line::lastWriteOf(std::string_view key) const {
    std::shared_lock lk(rw_mutex_);
    if (key == "**")
        return static_cast<std::int64_t>(records_.size());
    auto it = last_write_.find(std::string(key));
    std::int64_t v = (it != last_write_.end()) ? it->second : 0;
    auto hash_pos = key.find('#');
    if (hash_pos != std::string_view::npos) {
        auto wildcard = std::string(key.substr(0, hash_pos)) + "#*";
        auto wit = last_write_.find(wildcard);
        if (wit != last_write_.end() && wit->second > v)
            v = wit->second;
    }
    return v;
}

bool Line::isStale(std::vector<std::string> const &reads, std::int64_t base_n) const {
    std::shared_lock lk(rw_mutex_);
    for (auto const &r : reads) {
        if (lastWriteOf(r) > base_n)
            return true;
    }
    return false;
}

DomainLockManager::DomainGuard Line::lockDomains(std::vector<std::string> const &domains) {
    return domain_locks_.lock(domains);
}

void Line::apply(LandingRecord rec) {
    std::unique_lock lk(rw_mutex_);
    rec.n = static_cast<std::int64_t>(records_.size() + 1);
    roots_.push_back(rec.root);
    for (auto const &path : rec.paths) {
        last_write_[path] = rec.n;
        auto p = path;
        while (true) {
            auto slash = p.rfind('/');
            if (slash == std::string::npos)
                break;
            p = p.substr(0, slash);
            last_write_[p + "/"] = rec.n;
        }
    }
    last_write_["/"] = rec.n;
    last_write_["**"] = rec.n;
    for (auto const &d : rec.domains) {
        last_write_["@domain:" + d] = rec.n;
    }
    records_.push_back(std::move(rec));
}

std::vector<LandingRecord> Line::records(std::int64_t from, std::int64_t to) const {
    std::shared_lock lk(rw_mutex_);
    auto total = static_cast<std::int64_t>(records_.size());
    if (to < 0 || to > total)
        to = total;
    if (from < 0)
        from = 0;
    if (from >= to)
        return {};
    return std::vector<LandingRecord>(records_.begin() + from, records_.begin() + to);
}

std::unordered_map<std::string, int> Line::domainStats() const {
    std::shared_lock lk(rw_mutex_);
    std::unordered_map<std::string, int> stats;
    for (auto const &rec : records_) {
        if (rec.domains.size() > 1)
            stats["(cross-domain)"]++;
        for (auto const &d : rec.domains)
            stats[d]++;
    }
    return stats;
}

std::size_t Line::size() const {
    std::shared_lock lk(rw_mutex_);
    return records_.size();
}

Json Line::toJson() const {
    std::shared_lock lk(rw_mutex_);
    Json arr = Json::array();
    arr.push_back({{"n", 0}, {"root", roots_.front()}, {"created", 0}});
    for (auto const &r : records_) {
        if (!r.json.empty())
            arr.push_back(r.json);
        else {
            arr.push_back({{"n", r.n},
                           {"root", r.root},
                           {"stack", r.stack},
                           {"title", r.title},
                           {"principal", r.principal},
                           {"intent", r.intent},
                           {"route", r.route},
                           {"paths", r.paths},
                           {"domains", r.domains},
                           {"created", r.created}});
        }
    }
    return arr;
}

} // namespace axon
