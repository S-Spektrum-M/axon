#include "state.hpp"

#include <stdexcept>

namespace axon {
std::string_view tableName(StateTable table) {
    switch (table) {
    case StateTable::format:
        return "format";
    case StateTable::lines:
        return "lines";
    case StateTable::workspaces:
        return "workspaces";
    case StateTable::stacks:
        return "stacks";
    case StateTable::attestations:
        return "attestations";
    case StateTable::principals:
        return "principals";
    case StateTable::nonces:
        return "nonces";
    case StateTable::jobs:
        return "jobs";
    case StateTable::events:
        return "events";
    case StateTable::partitions:
        return "partitions";
    case StateTable::consumer_offsets:
        return "consumer_offsets";
    case StateTable::workflows:
        return "workflows";
    case StateTable::queue:
        return "queue";
    case StateTable::policy:
        return "policy";
    case StateTable::metrics:
        return "metrics";
    case StateTable::diagnostics:
        return "diagnostics";
    case StateTable::operations:
        return "operations";
    }
    throw std::logic_error("invalid state table");
}
namespace {
std::string pointer(std::string_view text) {
    std::string result;
    for (auto c : text) {
        if (c == '~')
            result += "~0";
        else if (c == '/')
            result += "~1";
        else
            result += c;
    }
    return result;
}
auto table(StateSnapshot const &state, std::string_view name) {
    auto it = state.tables.find(name);
    return it == state.tables.end() ? std::shared_ptr<StateSnapshot::Table const>{} : it->second;
}
auto cell(StateSnapshot const &state, std::string_view name, std::string_view key) {
    auto t = table(state, name);
    if (t) {
        auto it = t->records.find(key);
        if (it != t->records.end())
            return it->second;
    }
    return std::shared_ptr<Json const>{};
}
StateSnapshot::Table split(Json const &value) {
    StateSnapshot::Table result;
    result.type = value.type();
    if (value.is_structured()) {
        for (auto const &[key, item] : value.items())
            result.records[key] = std::make_shared<Json const>(item);
    } else
        result.records[""] = std::make_shared<Json const>(value);
    return result;
}
void diff(Json &out, Json const &before, Json const &after, std::string const &path) {
    for (auto operation : Json::diff(before, after)) {
        operation["path"] = path + operation.at("path").get<std::string>();
        out.push_back(std::move(operation));
    }
}
} // namespace
Json StateSnapshot::Table::json() const {
    if (type == Json::value_t::array) {
        auto result = Json::array();
        for (std::size_t i = 0; i < records.size(); ++i)
            result.push_back(*records.at(std::to_string(i)));
        return result;
    }
    if (type == Json::value_t::object) {
        auto result = Json::object();
        for (auto const &[key, item] : records)
            result[key] = *item;
        return result;
    }
    return records.empty() ? Json() : *records.at("");
}
StateSnapshot::StateSnapshot(Json const &value) {
    if (!value.is_object())
        throw std::runtime_error("database state must be an object");
    for (auto const &[name, item] : value.items())
        tables[name] = std::make_shared<Table const>(split(item));
}
Json StateSnapshot::json() const {
    auto result = Json::object();
    for (auto const &[name, item] : tables)
        result[name] = item->json();
    return result;
}
StateSnapshot StateSnapshot::patch(Json const &operations) const {
    auto result = *this;
    std::map<std::string, std::shared_ptr<Table>, std::less<>> changed;
    for (auto const &operation : operations) {
        if (operation.at("op") == "move" || operation.at("op") == "copy" || operation.at("op") == "test") {
            result = StateSnapshot(result.json().patch(Json::array({operation})));
            changed.clear();
            continue;
        }
        auto path = Json::json_pointer(operation.at("path").get<std::string>());
        if (path.empty()) {
            result = StateSnapshot(result.json().patch(Json::array({operation})));
            changed.clear();
            continue;
        }
        // json_pointer exposes decoded tokens through back()/parent_pointer().
        std::vector<std::string> tokens;
        while (!path.empty()) {
            tokens.insert(tokens.begin(), path.back());
            path = path.parent_pointer();
        }
        auto const &name = tokens[0];
        auto op = operation.at("op").get<std::string>();
        if (tokens.size() == 1) {
            if (op == "remove")
                result.tables.erase(name);
            else if (op == "add" || op == "replace")
                result.tables[name] = std::make_shared<Table const>(split(operation.at("value")));
            else
                result = StateSnapshot(result.json().patch(Json::array({operation})));
            changed.erase(name);
            continue;
        }
        if (!changed.contains(name)) {
            auto original = table(result, name);
            if (!original)
                throw std::runtime_error("patch references missing table");
            changed[name] = std::make_shared<Table>(*original);
            result.tables[name] = changed[name];
        }
        auto &target = *changed.at(name);
        auto key = tokens[1];
        bool append = target.type == Json::value_t::array && tokens.size() == 2 && op == "add" &&
                      (key == "-" || key == std::to_string(target.records.size()));
        if (append) {
            target.records[std::to_string(target.records.size())] = std::make_shared<Json const>(operation.at("value"));
        } else if (target.type == Json::value_t::array && tokens.size() == 2 && op != "replace") {
            auto local = operation;
            local["path"] = "/" + pointer(key);
            target = split(target.json().patch(Json::array({local})));
        } else if (tokens.size() == 2 && (op == "add" || op == "replace")) {
            target.records[key] = std::make_shared<Json const>(operation.at("value"));
        } else if (tokens.size() == 2 && op == "remove") {
            target.records.erase(key);
        } else {
            auto local = operation;
            std::string suffix;
            for (std::size_t i = 2; i < tokens.size(); ++i)
                suffix += "/" + pointer(tokens[i]);
            local["path"] = suffix;
            target.records[key] = std::make_shared<Json const>(target.records.at(key)->patch(Json::array({local})));
        }
    }
    return result;
}
StateTransaction::StateTransaction(StateSnapshot snapshot) : base_(std::move(snapshot)) {
}
bool StateTransaction::empty() const {
    return base_.tables.empty();
}
bool StateTransaction::contains(std::string_view name) const {
    reads_.insert(std::string(name));
    return fields_.contains(name) || base_.tables.contains(name);
}
Json const &StateTransaction::at(std::string_view name) const {
    reads_.insert(std::string(name));
    auto key = std::string(name);
    if (!fields_.contains(key)) {
        auto original = table(base_, name);
        if (!original)
            throw std::out_of_range("missing state table: " + key);
        auto value = original->json();
        for (auto const &[entry, item] : records_)
            if (entry.first == name && (edited_.contains(entry) || removed_.contains(entry))) {
                if (removed_.contains(entry))
                    value.erase(entry.second);
                else
                    value[entry.second] = item;
            }
        fields_[key] = std::move(value);
    }
    return fields_.at(key);
}
Json &StateTransaction::operator[](std::string_view name) {
    if (!contains(name))
        fields_[std::string(name)] = nullptr;
    (void)at(name);
    return fields_.at(std::string(name));
}
Json StateTransaction::value(std::string_view name, Json const &fallback) const {
    return contains(name) ? at(name) : fallback;
}
Json const &StateTransaction::record(std::string_view name, std::string_view key) const {
    if (fields_.contains(name)) {
        auto const &field = fields_.at(std::string(name));
        static Json const absent;
        return field.contains(key) ? field.at(key) : absent;
    }
    RecordKey entry{std::string(name), std::string(key)};
    if (!records_.contains(entry)) {
        auto original = cell(base_, name, key);
        records_[entry] = original ? *original : Json();
    }
    return records_.at(entry);
}
Json &StateTransaction::edit(std::string_view name, std::string_view key) {
    if (fields_.contains(name))
        return fields_.at(std::string(name))[std::string(key)];
    (void)record(name, key);
    RecordKey entry{std::string(name), std::string(key)};
    removed_.erase(entry);
    edited_.insert(entry);
    return records_.at(entry);
}
void StateTransaction::erase(std::string_view name, std::string_view key) {
    if (fields_.contains(name))
        fields_.at(std::string(name)).erase(std::string(key));
    else {
        (void)record(name, key);
        removed_.insert({std::string(name), std::string(key)});
    }
}
void StateTransaction::emit(Json event) {
    events_.push_back(std::move(event));
}
Json StateTransaction::json() const {
    for (auto const &[name, unused] : base_.tables) {
        (void)unused;
        (void)at(name);
    }
    auto result = Json::object();
    for (auto const &[name, value] : fields_)
        result[name] = value;
    return result;
}
bool StateTransaction::valid(StateSnapshot const &current) const {
    for (auto const &name : reads_)
        if (table(base_, name) != table(current, name))
            return false;
    for (auto const &[entry, unused] : records_) {
        (void)unused;
        if (!reads_.contains(entry.first) &&
            cell(base_, entry.first, entry.second) != cell(current, entry.first, entry.second))
            return false;
    }
    return true;
}
Json StateTransaction::changes(StateSnapshot const &current) const {
    auto patch = Json::array();
    for (auto const &[name, value] : fields_) {
        auto original = table(base_, name);
        if (!original)
            patch.push_back({{"op", "add"}, {"path", "/" + pointer(name)}, {"value", value}});
        else
            diff(patch, original->json(), value, "/" + pointer(name));
    }
    std::set<std::string> created_tables;
    for (auto const &[entry, value] : records_) {
        if (fields_.contains(entry.first))
            continue;
        auto original = cell(base_, entry.first, entry.second);
        auto path = "/" + pointer(entry.first) + "/" + pointer(entry.second);
        if (removed_.contains(entry)) {
            if (original)
                patch.push_back({{"op", "remove"}, {"path", path}});
        } else if (!original) {
            if (!value.is_null()) {
                if (!table(current, entry.first) && created_tables.insert(entry.first).second)
                    patch.push_back({{"op", "add"}, {"path", "/" + pointer(entry.first)}, {"value", Json::object()}});
                patch.push_back({{"op", "add"}, {"path", path}, {"value", value}});
            }
        } else
            diff(patch, *original, value, path);
    }
    auto events = table(current, "events");
    auto offset = events ? events->records.size() : 0;
    std::map<std::string, Json> partitions;
    for (auto event : events_) {
        auto part = event.at("partition").get<std::string>();
        if (!partitions.contains(part)) {
            auto original = cell(current, "partitions", part);
            partitions[part] = original ? *original : Json::array();
        }
        auto &stream = partitions.at(part);
        event["id"] = part + ":" + std::to_string(stream.size());
        event["offset"] = offset++;
        patch.push_back({{"op", "add"}, {"path", "/events/-"}, {"value", event}});
        stream.push_back(std::move(event));
    }
    for (auto const &[part, stream] : partitions) {
        auto original = cell(current, "partitions", part);
        auto path = "/partitions/" + pointer(part);
        if (original)
            diff(patch, *original, stream, path);
        else
            patch.push_back({{"op", "add"}, {"path", path}, {"value", stream}});
    }
    return patch;
}
} // namespace axon
