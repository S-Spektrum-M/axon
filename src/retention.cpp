#include "retention.hpp"

#include <set>

namespace axon {
Json pruneMetadata(StateTransaction &state, std::int64_t cutoff, std::size_t keep, bool dry_run) {
    // Preview uses the same transaction transformations, discarded by the caller.
    auto preview = state;
    auto &target = dry_run ? preview : state;
    Json counts{{"workspaces", 0}, {"stacks", 0}, {"jobs", 0}, {"attestations", 0}, {"snapshots", 0}, {"events", 0}};
    std::set<std::string> pinned;
    auto pin = [&pinned](auto const &self, Json const &value) -> void {
        if (value.is_object()) {
            for (auto const &[key, child] : value.items()) {
                if (key == "root" && child.is_string())
                    pinned.insert(child.template get<std::string>());
                else
                    self(self, child);
            }
        } else if (value.is_array())
            for (auto const &child : value)
                self(self, child);
    };
    auto &workspaces = target[StateTable::workspaces];
    for (auto it = workspaces.begin(); it != workspaces.end();) {
        auto const &ws = it.value();
        if (ws.at("touched").get<std::int64_t>() + ws.at("ttl").get<std::int64_t>() < now() &&
            ws.at("touched").get<std::int64_t>() < cutoff) {
            it = workspaces.erase(it);
            counts["workspaces"] = counts["workspaces"].get<int>() + 1;
        } else {
            pin(pin, ws);
            ++it;
        }
    }
    auto &stacks = target[StateTable::stacks];
    for (auto it = stacks.begin(); it != stacks.end();) {
        auto const &stack = it.value();
        auto status = stack.value("status", "");
        if ((status == "landed" || status == "abandoned" || status == "superseded" || status == "ejected" ||
             status == "rejected") &&
            stack.value("created", std::int64_t{0}) < cutoff) {
            it = stacks.erase(it);
            counts["stacks"] = counts["stacks"].get<int>() + 1;
        } else {
            pin(pin, stack);
            ++it;
        }
    }
    auto &jobs = target[StateTable::jobs];
    for (auto it = jobs.begin(); it != jobs.end();) {
        if (it.value().value("status", "") == "done" && it.value().value("lease_until", std::int64_t{0}) < cutoff) {
            it = jobs.erase(it);
            counts["jobs"] = counts["jobs"].get<int>() + 1;
        } else
            ++it;
    }
    auto &attestations = target[StateTable::attestations];
    for (auto it = attestations.begin(); it != attestations.end();) {
        auto expires = it->value("expires", std::int64_t{0});
        if (expires != 0 && expires < now() && it->value("created", std::int64_t{0}) < cutoff) {
            it = attestations.erase(it);
            counts["attestations"] = counts["attestations"].get<int>() + 1;
        } else
            ++it;
    }
    for (auto &[name, line] : target[StateTable::lines].items()) {
        (void)name;
        for (std::size_t i = 0; i + keep < line.size(); ++i) {
            auto &entry = line[i];
            if (!entry.value("pruned", false) && entry.value("created", std::int64_t{0}) < cutoff &&
                !pinned.contains(entry.value("root", ""))) {
                entry = {{"n", entry.at("n")}, {"created", entry.at("created")}, {"pruned", true}};
                counts["snapshots"] = counts["snapshots"].get<int>() + 1;
            }
        }
    }
    auto prune_event = [cutoff](Json &event) {
        if (event.value("created", std::int64_t{0}) < cutoff && event.value("kind", "") != "pruned") {
            event = {{"id", event.at("id")},
                     {"offset", event.at("offset")},
                     {"partition", event.at("partition")},
                     {"kind", "pruned"},
                     {"type", "pruned"},
                     {"created", event.at("created")},
                     {"data", Json::object()}};
            return true;
        }
        return false;
    };
    for (auto &event : target[StateTable::events])
        if (prune_event(event))
            counts["events"] = counts["events"].get<int>() + 1;
    for (auto &partition : target[StateTable::partitions])
        for (auto &event : partition)
            (void)prune_event(event);
    counts["dry_run"] = dry_run;
    counts["cutoff"] = cutoff;
    counts["keep"] = keep;
    return counts;
}
} // namespace axon
