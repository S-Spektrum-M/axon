#include "policy.hpp"

#include <limits>
#include <set>
#include <stdexcept>

namespace axon {
namespace {
void require(bool valid, std::string_view message) {
    if (!valid)
        throw std::runtime_error("invalid policy: " + std::string(message));
}
void fields(Json const &object, std::set<std::string> const &allowed) {
    require(object.is_object(), "expected an object");
    for (auto const &[key, value] : object.items()) {
        (void)value;
        require(allowed.contains(key), "unknown field " + key);
    }
}
void strings(Json const &values) {
    require(values.is_array(), "expected a string array");
    for (auto const &value : values)
        require(value.is_string() && !value.get_ref<std::string const &>().empty(), "expected nonempty strings");
}
void requirements(Json const &object) {
    fields(object, {"review", "review_by_group", "attestations"});
    for (auto const &[key, value] : object.items()) {
        if (key == "review")
            require(value.is_boolean(), "review must be boolean");
        else
            strings(value);
    }
}
} // namespace
void validatePolicy(Json const &policy) {
    fields(policy, {"defaults", "rules", "limits", "fast_path_attestations", "session_scoped_reads", "eject_failing"});
    for (auto key : {"fast_path_attestations", "session_scoped_reads", "eject_failing"})
        if (policy.contains(key))
            require(policy.at(key).is_boolean(), std::string(key) + " must be boolean");
    if (policy.contains("defaults")) {
        fields(policy.at("defaults"), {"human", "agent", "service"});
        for (auto const &value : policy.at("defaults"))
            requirements(value);
    }
    if (policy.contains("limits")) {
        fields(policy.at("limits"), {"max_affected_targets", "landings_per_minute", "speculative_window"});
        for (auto const &value : policy.at("limits"))
            require(value.is_number_integer() && value >= 0 && value <= std::numeric_limits<int>::max(),
                    "limits must be nonnegative integers fitting int");
    }
    if (!policy.contains("rules"))
        return;
    require(policy.at("rules").is_array(), "rules must be an array");
    std::set<std::string> names;
    for (auto const &rule : policy.at("rules")) {
        fields(rule, {"name", "when", "deny", "require", "waive_review", "forbid_assume_unrelated"});
        require(rule.contains("name") && rule.at("name").is_string() && !rule.at("name").get<std::string>().empty(),
                "rule needs a nonempty name");
        require(names.insert(rule.at("name").get<std::string>()).second, "duplicate rule name");
        if (rule.contains("deny"))
            require(rule.at("deny").is_string(), "deny must be a string");
        for (auto key : {"waive_review", "forbid_assume_unrelated"})
            if (rule.contains(key))
                require(rule.at(key).is_boolean(), std::string(key) + " must be boolean");
        if (rule.contains("require"))
            requirements(rule.at("require"));
        if (!rule.contains("when"))
            continue;
        auto const &when = rule.at("when");
        fields(when,
               {"principal_class",
                "principal",
                "any_path",
                "read_any",
                "all_paths_within",
                "write_outside",
                "intent",
                "intent_not",
                "labels_any",
                "policy_class",
                "affected_any",
                "assume_unrelated",
                "imported"});
        for (auto const &[key, value] : when.items()) {
            if (key == "assume_unrelated" || key == "imported")
                require(value.is_boolean(), key + " must be boolean");
            else {
                strings(value);
                if (key == "principal_class")
                    for (auto const &item : value)
                        require(item == "human" || item == "agent" || item == "service", "unknown principal class");
                if (key == "intent" || key == "intent_not")
                    for (auto const &item : value)
                        require(
                            std::set<std::string>{
                                "rename", "fix", "refactor", "feature", "test", "dep_bump", "freeform"}
                                .contains(item.get<std::string>()),
                            "unknown intent");
            }
        }
    }
}
} // namespace axon
