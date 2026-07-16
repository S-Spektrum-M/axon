#pragma once

#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace axon {
using Json = nlohmann::json;

enum class StateTable {
    format,
    lines,
    workspaces,
    stacks,
    attestations,
    principals,
    nonces,
    jobs,
    events,
    partitions,
    consumer_offsets,
    workflows,
    queue,
    policy,
    metrics,
    diagnostics,
    operations
};
[[nodiscard]] std::string_view tableName(StateTable table);

// Immutable metadata snapshots share both tables and records. JSON remains the
// on-disk/wire representation; transactions own only records they change.
class StateSnapshot {
public:
    struct Table {
        Json::value_t type = Json::value_t::null;
        std::map<std::string, std::shared_ptr<Json const>, std::less<>> records;
        [[nodiscard]] Json json() const;
    };
    std::map<std::string, std::shared_ptr<Table const>, std::less<>> tables;
    StateSnapshot() = default;
    explicit StateSnapshot(Json const &value);
    [[nodiscard]] Json json() const;
    [[nodiscard]] StateSnapshot patch(Json const &operations) const;
};

class StateTransaction {
public:
    explicit StateTransaction(StateSnapshot snapshot);
    [[nodiscard]] Json const &at(StateTable table) const {
        return at(tableName(table));
    }
    [[nodiscard]] Json &operator[](StateTable table) {
        return (*this)[tableName(table)];
    }
    [[nodiscard]] Json value(StateTable table, Json const &fallback) const {
        return value(tableName(table), fallback);
    }
    [[nodiscard]] Json const &record(StateTable table, std::string_view key) const {
        return record(tableName(table), key);
    }
    [[nodiscard]] Json &edit(StateTable table, std::string_view key) {
        return edit(tableName(table), key);
    }
    void erase(StateTable table, std::string_view key) {
        erase(tableName(table), key);
    }
    [[nodiscard]] bool empty() const;
    [[nodiscard]] Json const &at(std::string_view table) const;
    [[nodiscard]] Json &operator[](std::string_view table);
    [[nodiscard]] Json value(std::string_view table, Json const &fallback) const;
    [[nodiscard]] bool contains(std::string_view table) const;
    [[nodiscard]] Json const &record(std::string_view table, std::string_view key) const;
    // Row references must not be retained across materializing that whole table.
    [[nodiscard]] Json &edit(std::string_view table, std::string_view key);
    void erase(std::string_view table, std::string_view key);
    void emit(Json event);
    [[nodiscard]] Json json() const;
    [[nodiscard]] bool valid(StateSnapshot const &current) const;
    [[nodiscard]] Json changes(StateSnapshot const &current) const;

private:
    using RecordKey = std::pair<std::string, std::string>;
    StateSnapshot base_;
    mutable std::map<std::string, Json, std::less<>> fields_;
    mutable std::set<std::string, std::less<>> reads_;
    mutable std::map<RecordKey, Json> records_;
    std::set<RecordKey> removed_;
    std::set<RecordKey> edited_;
    std::vector<Json> events_;
};
} // namespace axon
