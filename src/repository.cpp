#include "repository.hpp"

#include "filesystem.hpp"
#include "graph.hpp"
#include "policy.hpp"
#include "retention.hpp"
#include "symbols.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <iostream>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <stdexcept>
#include <thread>

namespace axon {
namespace {
void require(bool condition, std::string_view message) {
    if (!condition)
        throw std::runtime_error(std::string(message));
}
std::string str(Json const &object, std::string_view key, std::string_view fallback = "") {
    return object.value(std::string(key), std::string(fallback));
}
Json array(Json const &object, std::string_view key) {
    return object.value(std::string(key), Json::array());
}
Json array(StateTransaction const &state, std::string_view key) {
    return state.value(key, Json::array());
}
std::vector<std::string> strings(Json const &value) {
    return value.get<std::vector<std::string>>();
}
bool includes(Json const &values, std::string_view value) {
    return std::ranges::any_of(values, [value](Json const &item) { return item == value; });
}
void add(Json &values, std::string_view value) {
    if (!includes(values, value)) {
        values.push_back(value);
        std::sort(values.begin(), values.end());
    }
}
bool admin(StateTransaction const &state, std::string_view principal) {
    return includes(array(state.record(StateTable::principals, principal), "groups"), "admins");
}
std::string principalClass(std::string_view principal) {
    auto split = principal.find(':');
    require(split != std::string_view::npos && split + 1 < principal.size(), "invalid principal");
    auto kind = std::string(principal.substr(0, split));
    require(kind == "human" || kind == "agent" || kind == "service", "invalid principal class");
    if (kind != "human")
        require(principal.find('@', split + 2) != std::string_view::npos, "principal needs an owner");
    return kind;
}
bool matchAny(Json const &patterns, std::string_view path) {
    return std::ranges::any_of(patterns,
                               [path](Json const &pattern) { return axon::matches(pattern.get<std::string>(), path); });
}
bool anyPath(Json const &patterns, Json const &paths) {
    return std::ranges::any_of(paths,
                               [&patterns](Json const &path) { return matchAny(patterns, path.get<std::string>()); });
}
Json pathsOf(Json const &changes) {
    Json result = Json::array();
    for (auto const &change : changes)
        result.push_back(change.at("path"));
    return result;
}
std::string attestationStatus(StateTransaction const &state,
                              std::string_view target,
                              std::string_view input,
                              std::string_view kind) {
    std::string first, latest;
    bool disagree = false;
    int consecutive = 0;
    for (auto const &attestation : state.at(StateTable::attestations)) {
        if (attestation.at("target") != target || attestation.at("input_hash") != input ||
            attestation.at("kind") != kind)
            continue;
        if (attestation.value("expires", std::int64_t{0}) != 0 &&
            attestation.at("expires").get<std::int64_t>() <= axon::now())
            continue;
        auto result = str(attestation, "result");
        if (first.empty())
            first = result;
        disagree |= result != first;
        consecutive = result == latest ? consecutive + 1 : 1;
        latest = result;
    }
    if (latest.empty())
        return "missing";
    return disagree && consecutive < 3 ? "flaky" : latest;
}
Json defaultPolicy() {
    return Json{{"defaults",
                 {{"agent", {{"review", true}, {"attestations", {"tests"}}}},
                  {"human", {{"attestations", {"tests"}}}},
                  {"service", {{"attestations", {"tests"}}}}}},
                {"rules",
                 {{{"name", "agents-autoland-tests-docs"},
                   {"when", {{"principal_class", {"agent"}}, {"all_paths_within", {"tests/**", "docs/**"}}}},
                   {"waive_review", true}}}},
                {"limits", {{"max_affected_targets", 5000}, {"landings_per_minute", 600}}}};
}
Json seal(Json object, std::string_view principal, std::string_view seed) {
    object.erase("id");
    object.erase("signature");
    object["signer"] = principal;
    object["key"] = axon::publicKey(seed);
    object["signature"] = axon::sign(seed, object.dump());
    object["id"] = axon::hash(object.dump());
    return object;
}
std::int64_t parseDuration(std::string_view value, std::int64_t fallback) {
    if (value.empty())
        return fallback;
    std::size_t end = 0;
    auto number = std::stoll(std::string(value), &end);
    auto suffix = value.substr(end);
    std::int64_t multiplier = 1;
    if (suffix == "m")
        multiplier = 60;
    else if (suffix == "h")
        multiplier = 3600;
    else if (suffix == "d")
        multiplier = 86400;
    else
        require(suffix == "s" || suffix.empty(), "duration: use s, m, h or d");
    require(number > 0 && number <= 31536000 / multiplier, "duration out of range");
    return number * multiplier;
}
} // namespace
Json signedRequest(Json const &payload, std::string_view principal, std::string_view seed) {
    auto authenticated = payload;
    auto command = str(payload, "command");
    auto options = payload.value("options", Json::object());
    if (command == "agent-key") {
        auto name = payload.at("args").at(0).get<std::string>();
        auto created = axon::now();
        authenticated["binding"] = seal({{"type", "axon-agent-binding-1"},
                                         {"principal", "agent:" + name + "@" + std::string(principal.substr(6))},
                                         {"public_key", payload.at("public_key")},
                                         {"owner", principal},
                                         {"created", created},
                                         {"expires", created + parseDuration(str(options, "ttl"), 86400)}},
                                        principal,
                                        seed);
    }
    if (command == "attest" || command == "review") {
        auto created = axon::now();
        Json claim{
            {"type", "axon-attestation-1"},
            {"target", command == "review" ? "review:stack" : str(options, "target")},
            {"input_hash", command == "review" ? str(payload, "review_subject") : str(options, "input")},
            {"kind", command == "review" ? "reviewed_by" : str(options, "kind")},
            {"result",
             command == "review" ? (str(options, "reject") == "true" ? "failed" : "passed") : str(options, "result")},
            {"created", created},
            {"nonce", axon::randomHex()},
            {"expires", str(options, "ttl").empty() ? 0 : created + parseDuration(str(options, "ttl"), 0)}};
        if (command == "review")
            claim["detail"] = str(options, "m");
        authenticated["attestation"] = seal(claim, principal, seed);
    }
    if (command == "job-complete") {
        authenticated["completion"] = seal({{"type", "axon-executor-completion-1"},
                                            {"job", payload.at("args").at(0)},
                                            {"lease", payload.at("lease")},
                                            {"result", options.at("result")},
                                            {"evidence_hash", axon::hash(axon::unhex(str(payload, "input")))},
                                            {"created", axon::now()}},
                                           principal,
                                           seed);
    }
    Json envelope{{"protocol", 1},
                  {"principal", principal},
                  {"created", axon::now()},
                  {"nonce", axon::randomHex()},
                  {"payload", authenticated}};
    envelope["signature"] = axon::sign(seed, envelope.dump());
    return envelope;
}
Repository::Repository(Path const &directory, bool execute_builds, bool no_sync)
    : database_(directory, no_sync), store_(directory), directory_(std::filesystem::absolute(directory)),
      execute_builds_(execute_builds) {
}
void Repository::initialize(std::string_view principal, std::string_view key) {
    std::unique_lock lock(maintenance_mutex_);
    require(database_.state().empty(), "repository is already initialized");
    require(principalClass(principal) == "human", "admin must be human:<name>");
    require(key.size() == 64, "invalid public key");
    (void)axon::unhex(key);
    auto root = store_.empty();
    auto seed = axon::randomHex(32);
    axon::writeFile(directory_ / "sequencer.key", seed);
    Json state{
        {"format", "axon-1"},
        {"lines", {{"trunk", Json::array({Json{{"n", 0}, {"root", root}, {"created", axon::now()}}})}}},
        {"workspaces", Json::object()},
        {"stacks", Json::object()},
        {"attestations", Json::array()},
        {"principals", {{std::string(principal), {{"key", key}, {"groups", {"admins"}}, {"expires", 0}}}}},
        {"nonces", Json::object()},
        {"jobs", Json::object()},
        {"events", Json::array()},
        {"partitions", Json::object()},
        {"consumer_offsets", Json::object()},
        {"workflows", Json::array({{{"name", "tests"}, {"on", "head_moved"}, {"kind", "tests"}, {"gate", true}}})},
        {"queue", Json::array()},
        {"policy", defaultPolicy()},
        {"metrics", Json::object()}};
    database_.commit(state);
}
Json Repository::inspect() const {
    std::shared_lock lock(maintenance_mutex_);
    return database_.state();
}
Json Repository::identity(std::string_view principal) const {
    return database_.transaction().record(StateTable::principals, principal);
}
std::expected<Json, std::string> Repository::request(Json const &envelope) {
    try {
        std::shared_lock shared(maintenance_mutex_, std::defer_lock);
        std::unique_lock exclusive(maintenance_mutex_, std::defer_lock);
        auto payload = envelope.value("payload", Json::object());
        auto args = payload.value("args", Json::array());
        bool maintenance = str(payload, "command") == "admin" && !args.empty() &&
                           (args[0] == "gc" || args[0] == "compact" || args[0] == "prune");
        if (maintenance)
            exclusive.lock();
        else
            shared.lock();
        // Authenticate before waiting on domain ownership or inspecting workspace trees.
        // The transaction below rechecks identity/expiry after acquiring its locks.
        auto initial = database_.transaction();
        require(!initial.empty(), "repository is not initialized");
        auto caller = envelope.at("principal").get<std::string>();
        auto registered = initial.record(StateTable::principals, caller);
        require(!registered.is_null(), "unknown principal");
        auto signed_body = envelope;
        signed_body.erase("signature");
        require(axon::verify(str(registered, "key"), signed_body.dump(), str(envelope, "signature")),
                "invalid request signature");
        for (;;) {
            auto state = database_.transaction();
            auto domains = preparationDomains(state, payload);
            auto domain_guard = domain_locks_.lock(domains);
            state = database_.transaction();
            auto required_domains = preparationDomains(state, payload);
            if (!std::ranges::includes(domains, required_domains))
                continue;
            require(!state.empty(), "repository is not initialized");
            require(envelope.at("protocol") == 1, "unsupported RPC protocol");
            auto principal = envelope.at("principal").get<std::string>();
            auto identity = state.record(StateTable::principals, principal);
            require(!identity.is_null(), "unknown principal");
            require(identity.value("expires", std::int64_t{0}) == 0 ||
                        identity.at("expires").get<std::int64_t>() > axon::now(),
                    "expired identity");
            auto timestamp = envelope.at("created").get<std::int64_t>();
            require(timestamp >= axon::now() - 300 && timestamp <= axon::now() + 300,
                    "request timestamp outside allowed skew");
            auto nonce = envelope.at("nonce").get<std::string>();
            require(nonce.size() == 32, "invalid nonce");
            auto unsigned_envelope = envelope;
            unsigned_envelope.erase("signature");
            require(axon::verify(identity.at("key").get<std::string>(),
                                 unsigned_envelope.dump(),
                                 envelope.at("signature").get<std::string>()),
                    "invalid request signature");
            require(state.record(StateTable::nonces, nonce).is_null(), "replayed request");
            state.edit(StateTable::nonces, nonce) = timestamp;
            for (auto name : {"binding", "attestation", "completion"}) {
                if (!envelope.at("payload").contains(name))
                    continue;
                auto statement = envelope.at("payload").at(name);
                auto id = str(statement, "id");
                statement.erase("id");
                require(axon::hash(statement.dump()) == id, "invalid statement ID");
                auto signature = str(statement, "signature");
                statement.erase("signature");
                require(str(statement, "signer") == principal && statement.at("key") == identity.at("key") &&
                            axon::verify(str(identity, "key"), statement.dump(), signature),
                        "invalid statement signature");
                auto created = statement.at("created").get<std::int64_t>();
                require(created >= axon::now() - 300 && created <= axon::now() + 300,
                        "statement timestamp outside allowed skew");
            }
            auto operation = str(payload, "operation_id");
            auto operation_key = principal + "/" + operation;
            auto digest = axon::hash(payload.dump());
            Json result;
            auto previous = operation.empty() ? Json() : state.record(StateTable::operations, operation_key);
            if (!previous.is_null()) {
                require(previous.at("digest") == digest, "operation ID reused with different payload");
                result = previous.at("result");
            } else {
                if (!operation.empty()) {
                    require(operation.size() == 32 &&
                                operation.find_first_not_of("0123456789abcdef") == std::string::npos,
                            "invalid operation ID");
                    auto command = str(payload, "command");
                    require(command == "write" || command == "rm" || command == "mv",
                            "operation IDs support workspace edits only");
                }
                result = execute(state, principal, payload);
                if (!operation.empty())
                    state.edit(StateTable::operations,
                               operation_key) = {{"digest", digest}, {"result", result}, {"created", axon::now()}};
            }
            // Keep the original authenticated request, independently verifiable after
            // an identity rotates its key. Mutable status is outside signed submission.
            if (envelope.at("payload").contains("attestation") || str(envelope.at("payload"), "command") == "stack") {
                auto proof = Json{{"request", envelope}, {"key", identity.at("key")}};
                event(state, "authenticated_request", proof);
            }
            if (!database_.commit(state)) {
                std::this_thread::yield();
                continue;
            }
            if (str(envelope.at("payload"), "command") == "admin" &&
                array(envelope.at("payload"), "args") == Json::array({"compact"}))
                database_.compact();
            return result;
        }
    } catch (std::exception const &error) {
        return std::unexpected(error.what());
    }
}
void Repository::runExecutor(std::stop_token stop) {
    if (!execute_builds_)
        return;
    std::mutex sleep_mutex;
    std::condition_variable_any wake;
    auto seed = axon::readFile(directory_ / "sequencer.key");
    constexpr auto worker = "service:executor@axon";
    while (!stop.stop_requested()) {
        try {
            Json job;
            {
                std::shared_lock lock(maintenance_mutex_);
                for (;;) {
                    auto state = database_.transaction();
                    job = execute(state, worker, {{"command", "job-claim"}, {"omit_contents", true}});
                    if (job.is_null() || database_.commit(state))
                        break;
                    std::this_thread::yield();
                }
            }
            if (job.is_null()) {
                std::unique_lock lock(sleep_mutex);
                wake.wait_for(lock, stop, std::chrono::milliseconds(100), [] { return false; });
                continue;
            }
            auto work = directory_ / "work" / axon::randomHex();
            ProcessResult result;
            try {
                axon::materialize(store_, job.at("files"), work);
                std::vector<std::string> args{"env"};
                for (auto const &[key, value] : job.at("definition").value("env", Json::object()).items())
                    args.push_back(key + "=" + value.get<std::string>());
                args.insert(args.end(), {"sh", "-c", str(job.at("definition"), "cmd")});
                result = axon::runProcess(args, work, "", 60, stop);
            } catch (std::exception const &error) {
                result = {126, error.what()};
            }
            std::error_code ignored;
            std::filesystem::remove_all(work, ignored);
            if (stop.stop_requested())
                return; // The durable lease makes interrupted jobs reclaimable.
            std::shared_lock lock(maintenance_mutex_);
            for (;;) {
                auto state = database_.transaction();
                auto domains = preparationDomains(state, {{"command", "job-complete"}});
                auto domain_guard = domain_locks_.lock(domains);
                state = database_.transaction();
                if (!std::ranges::includes(domains, preparationDomains(state, {{"command", "job-complete"}})))
                    continue;
                auto claim = execute(state,
                                     worker,
                                     {{"command", "job-complete"},
                                      {"args", {job.at("id")}},
                                      {"options", {{"result", result.status == 0 ? "passed" : "failed"}}},
                                      {"input", axon::hex(result.output)},
                                      {"lease", job.at("lease")}},
                                     true);
                event(state, "executor_receipt", seal(claim, worker, seed));
                if (database_.commit(state))
                    break;
                std::this_thread::yield();
            }
        } catch (std::exception const &error) {
            std::cerr << "axon executor: " << error.what() << '\n';
            std::unique_lock lock(sleep_mutex);
            wake.wait_for(lock, stop, std::chrono::seconds(1), [] { return false; });
        }
    }
}
void Repository::event(StateTransaction &state, std::string_view kind, Json const &data, std::string_view partition) {
    std::string part_str(partition);
    if (part_str.empty()) {
        if (data.is_object() && data.contains("line"))
            part_str = "line-" + data["line"].get<std::string>();
        else
            part_str = "events";
    }
    if (kind == "workspace_changed" || kind == "stack_submitted") {
        for (auto const &workflow : array(state, "workflows")) {
            if (str(workflow, "on") != kind)
                continue;
            auto root = kind == "workspace_changed" ? str(data, "root")
                                                    : str(state[StateTable::stacks][str(data, "stack")], "root");
            auto graph = GraphCache::get(store_, root, build_query_);
            Json targets = Json::array();
            for (auto const &[label, definition] : graph->targets().items()) {
                (void)definition;
                targets.push_back(label);
            }
            (void)checkBuilds(state, root, targets, true, str(workflow, "kind"));
        }
    }
    state.emit({{"partition", part_str}, {"kind", kind}, {"type", kind}, {"created", axon::now()}, {"data", data}});
}
Json Repository::filterEvents(StateTransaction const &state,
                              std::size_t offset,
                              std::string_view partition,
                              std::string_view line,
                              std::vector<std::string> const &paths) {
    Json result = Json::array();
    if (!partition.empty() && !state.at(StateTable::partitions).contains(std::string(partition)))
        return result;
    auto const &ev_list =
        partition.empty() ? state.at(StateTable::events) : state.at(StateTable::partitions).at(std::string(partition));
    for (auto const &ev : ev_list) {
        if (ev.at("offset").get<std::size_t>() < offset)
            continue;
        auto data = ev.value("data", Json::object());
        if (!line.empty() && ev.value("partition", "") != "line-" + std::string(line) &&
            (!data.is_object() || str(data, "line") != line))
            continue;
        if (!paths.empty()) {
            Json event_paths = data.is_object() ? array(data, "paths") : Json::array();
            if (data.is_object() && data.contains("path"))
                event_paths.push_back(data.at("path"));
            bool hit = false;
            for (auto const &path : event_paths)
                for (auto const &glob : paths)
                    hit |= axon::matches(glob, path.get<std::string>());
            if (!hit)
                continue;
        }
        result.push_back(ev);
    }
    return result;
}
Json Repository::eventsSince(std::size_t offset,
                             std::string_view partition,
                             std::string_view line,
                             std::vector<std::string> const &paths) const {
    std::shared_lock lock(maintenance_mutex_);
    return filterEvents(database_.transaction(), offset, partition, line, paths);
}
std::string Repository::metricsPrometheus() const {
    std::shared_lock lock(maintenance_mutex_);
    auto m = [](StateTransaction const &state) {
        auto result = state.value(StateTable::metrics, Json::object());
        result["stacks_submitted"] = state.at(StateTable::stacks).size();
        result["attestations"] = state.at(StateTable::attestations).size();
        std::size_t queued = 0;
        for (auto const &stack : state.at(StateTable::stacks))
            if (stack.value("queued", false) &&
                (str(stack, "status") == "submitted" || str(stack, "status") == "blocked"))
                ++queued;
        result["queue_depth"] = queued;
        return result;
    }(database_.transaction());
    std::ostringstream out;
    auto write_metric = [&out](std::string_view name, std::int64_t val) {
        out << "axon_" << name << " " << val << "\n";
    };
    auto fast = m.value("fast", 0);
    auto rebase = m.value("rebase", 0);
    auto merge = m.value("merge", 0);
    auto imported = m.value("import", 0);
    auto total_landings = fast + rebase + merge + imported;
    write_metric("landings_total", total_landings);
    write_metric("landings_fast_path_total", fast);
    write_metric("landings_auto_rebase_total", rebase);
    write_metric("landings_text_merge_total", merge);
    write_metric("landings_import_total", imported);
    write_metric("landings_cross_domain_total", m.value("cross_domain", 0));
    write_metric("stacks_submitted_total", m.value("stacks_submitted", 0));
    write_metric("stacks_conflicted_total", m.value("conflicted", 0));
    write_metric("stacks_ejected_total", m.value("ejections", 0));
    write_metric("stacks_rejected_total", m.value("rejections", 0));
    write_metric("attestations_total", m.value("attestations", 0));
    write_metric("attestation_reuse_hits_total", m.value("attestation_reuse_hits", 0));
    write_metric("merge_queue_depth", m.value("queue_depth", 0));
    write_metric("bisect_steps_total", m.value("bisect_steps", 0));
    write_metric("coalesce_windows_total", m.value("coalesce_windows", 0));
    return out.str();
}

Json Repository::snapshot(StateTransaction const &state, std::string_view position) const {
    if (position.empty())
        position = "trunk";
    auto at = position.find('@');
    auto name = std::string(position.substr(0, at));
    require(state.at(StateTable::lines).contains(name), "unknown line " + name);
    auto const &line = state.at(StateTable::lines).at(name);
    if (at == std::string_view::npos)
        return Json{{"line", name}, {"n", line.size() - 1}, {"root", line.back().at("root")}};
    auto text = std::string(position.substr(at + 1));
    std::size_t end = 0;
    auto n = std::stoll(text, &end);
    require(end == text.size() && n >= 0 && static_cast<std::size_t>(n) < line.size(), "unknown snapshot");
    require(!line.at(n).value("pruned", false), "snapshot was pruned by retention");
    return Json{{"line", name}, {"n", n}, {"root", line.at(n).at("root")}};
}
Json &Repository::workspace(StateTransaction &state, std::string_view id, std::string_view principal) {
    require(!state.record(StateTable::workspaces, id).is_null(), "unknown workspace");
    auto &ws = state.edit(StateTable::workspaces, id);
    require(ws.at("owner") == principal || admin(state, principal), "workspace belongs to another principal");
    require(ws.at("touched").get<std::int64_t>() + ws.at("ttl").get<std::int64_t>() >= axon::now(),
            "workspace expired");
    ws["touched"] = axon::now();
    return ws;
}
std::string Repository::stackId(StateTransaction const &state, std::string_view prefix) const {
    require(prefix.size() >= 4, "stack id must contain at least four characters");
    std::string result;
    for (auto const &[id, value] : state.at(StateTable::stacks).items()) {
        (void)value;
        if (!id.starts_with(prefix))
            continue;
        require(result.empty(), "ambiguous stack id");
        result = id;
    }
    require(!result.empty(), "unknown stack");
    return result;
}
Json Repository::forkWorkspace(StateTransaction &state, std::string_view principal, Json const &source) {
    Json base;
    std::string root;
    Json reads = Json::array();
    if (!str(source, "ws").empty()) {
        auto original = workspace(state, str(source, "ws"), principal);
        base = original.at("base");
        root = original.at("root");
        reads = original.at("reads");
    } else {
        base = snapshot(state, str(source, "from", "trunk"));
        root = base.at("root");
    }
    auto id = axon::randomHex();
    Json ws{{"id", id},
            {"owner", principal},
            {"base", base},
            {"root", root},
            {"reads", reads},
            {"drafts", Json::array()},
            {"session", str(source, "session")},
            {"created", axon::now()},
            {"touched", axon::now()},
            {"ttl", parseDuration(str(source, "ttl"), 7 * 86400)}};
    state.edit(StateTable::workspaces, id) = ws;
    event(state, "workspace_forked", {{"workspace", id}});
    return ws;
}
Json Repository::decision(StateTransaction const &state, Json const &stack, Json const &affected) const {
    auto policy = state.at(StateTable::policy);
    auto kind = principalClass(str(stack, "principal"));
    auto defaults = policy.value("defaults", Json::object()).value(kind, Json::object());
    Json result{{"review", defaults.value("review", false)},
                {"attestations", array(defaults, "attestations")},
                {"groups", array(defaults, "review_by_group")},
                {"matched", Json::array()},
                {"denied", ""}};
    auto paths = stack.at("write_set");
    bool explicit_review = false;
    bool waive = false;
    for (auto const &rule : array(policy, "rules")) {
        auto when = rule.value("when", Json::object());
        bool match = true;
        for (auto const &[key, values] : when.items()) {
            if (key == "principal_class")
                match &= includes(values, kind);
            else if (key == "principal")
                match &= matchAny(values, str(stack, "principal"));
            else if (key == "any_path")
                match &= anyPath(values, paths);
            else if (key == "read_any")
                match &= anyPath(values, stack.at("read_set"));
            else if (key == "all_paths_within")
                match &= !paths.empty() && std::ranges::all_of(paths, [&values](Json const &p) {
                    return matchAny(values, p.get<std::string>());
                });
            else if (key == "write_outside")
                match &= std::ranges::any_of(
                    paths, [&values](Json const &p) { return !matchAny(values, p.get<std::string>()); });
            else if (key == "intent")
                match &= includes(values, str(stack, "intent"));
            else if (key == "intent_not")
                match &= !includes(values, str(stack, "intent"));
            else if (key == "labels_any")
                match &= std::ranges::any_of(array(stack, "labels"), [&values](Json const &v) {
                    return includes(values, v.get<std::string>());
                });
            else if (key == "policy_class")
                match &= includes(values, str(stack, "policy_class"));
            else if (key == "affected_any")
                match &= anyPath(values, affected);
            else if (key == "assume_unrelated")
                match &= values == !array(stack, "assume_unrelated").empty();
            else if (key == "imported")
                match &= values == stack.value("imported", false);
            else
                throw std::runtime_error("unknown policy condition " + key);
        }
        if (!match)
            continue;
        result["matched"].push_back(rule.at("name"));
        if (!str(rule, "deny").empty())
            result["denied"] = str(rule, "deny");
        if (rule.value("forbid_assume_unrelated", false) && !array(stack, "assume_unrelated").empty())
            result["denied"] = "read narrowing forbidden";
        auto requirements = rule.value("require", Json::object());
        explicit_review |= requirements.value("review", false) || !array(requirements, "review_by_group").empty();
        for (auto const &attestation : array(requirements, "attestations"))
            add(result["attestations"], attestation.get<std::string>());
        for (auto const &group : array(requirements, "review_by_group"))
            add(result["groups"], group.get<std::string>());
        waive |= rule.value("waive_review", false);
    }
    result["review"] = explicit_review || (result["review"].get<bool>() && !waive) || !result["groups"].empty();
    auto limit = policy.value("limits", Json::object()).value("max_affected_targets", 0);
    if (limit > 0 && affected.size() > static_cast<std::size_t>(limit))
        result["denied"] = "affected-target limit exceeded";
    return result;
}
Json Repository::checkBuilds(
    StateTransaction &state, std::string_view root, Json const &targets, bool run, std::string_view kind) {
    auto graph = GraphCache::get(store_, root, build_query_);
    Json results = Json::array();
    for (auto const &name : targets) {
        auto definition_for_kind = graph->targets().at(name.get<std::string>()).at("def");
        auto target_kind = str(definition_for_kind, "kind", "test");
        if (target_kind != (kind == "tests" ? "test" : kind))
            continue;
        auto closure = graph->closure(name.get<std::string>());
        auto input = str(closure, "input_hash");
        Json found;
        for (auto const &attestation : state.at(StateTable::attestations)) {
            if (attestation.at("target") == name && attestation.at("input_hash") == input &&
                attestation.at("kind") == kind &&
                (attestation.value("expires", std::int64_t{0}) == 0 ||
                 attestation.at("expires").get<std::int64_t>() > axon::now()))
                found = attestation;
        }
        if (!found.is_null()) {
            auto hits = state[StateTable::metrics].value("attestation_reuse_hits", 0);
            state[StateTable::metrics]["attestation_reuse_hits"] = hits + 1;
        }
        if (found.is_null() && run) {
            auto definition = graph->targets().at(name.get<std::string>()).at("def");
            if (!str(definition, "cmd").empty()) {
                auto job_id = axon::hash(Json{{"target", name}, {"input", input}, {"kind", kind}}.dump());
                if (!state[StateTable::jobs].contains(job_id) ||
                    str(state[StateTable::jobs][job_id], "status") == "done") {
                    state[StateTable::jobs][job_id] = {{"id", job_id},
                                                       {"target", name},
                                                       {"input_hash", input},
                                                       {"kind", kind},
                                                       {"definition", definition},
                                                       {"files", closure.at("files")},
                                                       {"status", "pending"},
                                                       {"lease_until", 0}};
                    event(state, "job_ready", {{"job", job_id}});
                }
            }
        }
        results.push_back({{"target", name},
                           {"input_hash", input},
                           {"kind", kind},
                           {"status", attestationStatus(state, name.get<std::string>(), input, kind)}});
    }
    return results;
}
std::pair<std::string, std::string> Repository::blame(StateTransaction &state,
                                                      std::string_view candidate,
                                                      std::string_view head_root,
                                                      std::string_view target,
                                                      std::string_view kind) {
    (void)candidate;
    auto head_graph = GraphCache::get(store_, head_root, build_query_);
    if (!head_graph->targets().contains(std::string(target)))
        return {"eject", std::string(target) + " (new in this stack) fails"};
    auto head_closure = head_graph->closure(target);
    auto head_input = str(head_closure, "input_hash");
    auto head_status = attestationStatus(state, target, head_input, kind);
    if (head_status == "passed")
        return {"eject",
                std::string(target) + " " + std::string(kind) + " fails with this stack and passes without it"};
    if (head_status == "failed")
        return {"blocked", std::string(target) + " already fails on the line head"};
    auto head_checks = checkBuilds(state, head_root, Json::array({target}), true, kind);
    for (auto const &chk : head_checks) {
        if (chk.at("target") == target && chk.at("status") == "passed")
            return {"eject",
                    std::string(target) + " " + std::string(kind) + " fails with this stack and passes without it"};
    }
    return {"blocked", std::string(target) + " already fails on the line head"};
}
void Repository::coalesceAndBisect(StateTransaction &state, std::string_view line_name) {
    auto const &line = state[StateTable::lines][std::string(line_name)];
    if (line.size() < 2)
        return;
    auto tip = str(line.back(), "root");
    auto graph = GraphCache::get(store_, tip, build_query_);
    for (auto const &[label, target] : graph->targets().items()) {
        auto kind = str(target.at("def"), "kind", "test");
        if (kind == "test")
            kind = "tests";
        auto input = str(graph->closure(label), "input_hash");
        if (attestationStatus(state, label, input, kind) != "failed")
            continue;
        auto diagnosis = axon::hash(Json::array({line_name, line.back().at("n"), label, input, kind}).dump());
        if (state.value(StateTable::diagnostics, Json::object()).contains(diagnosis))
            continue;
        struct Candidate {
            std::size_t n;
            std::string root;
            std::string input;
        };
        std::vector<Candidate> candidates;
        std::string previous;
        for (std::size_t n = 0; n < line.size(); ++n) {
            if (line[n].value("pruned", false)) {
                candidates.clear();
                previous.clear();
                continue;
            }
            auto root = str(line[n], "root");
            auto historical = GraphCache::get(store_, root, build_query_);
            if (!historical->targets().contains(label)) {
                candidates.clear(); // A later reintroduction starts a new diagnostic window.
                previous.clear();
                continue;
            }
            auto hash = str(historical->closure(label), "input_hash");
            if (hash != previous) {
                candidates.push_back({n, root, hash});
                previous = hash;
            }
        }
        if (candidates.empty())
            continue;
        std::size_t low = 0, high = candidates.size() - 1;
        // Narrow to the last observed passing version, if any.
        for (std::size_t i = 0; i < high; ++i)
            if (attestationStatus(state, label, candidates[i].input, kind) == "passed")
                low = i + 1;
        bool pending = false;
        std::size_t steps = 0;
        while (low < high) {
            ++steps;
            auto middle = low + (high - low) / 2;
            auto status = attestationStatus(state, label, candidates[middle].input, kind);
            if (status == "missing") {
                (void)checkBuilds(state, candidates[middle].root, Json::array({label}), true, kind);
                pending = true;
                break;
            }
            if (status == "flaky") {
                pending = true;
                break;
            }
            if (status == "passed")
                low = middle + 1;
            else
                high = middle;
        }
        if (pending)
            continue; // A job completion resumes diagnosis using durable evidence.
        auto culprit = candidates[low].n;
        Json diagnosis_record{{"line", line_name},
                              {"n", culprit},
                              {"target", label},
                              {"kind", kind},
                              {"input_hash", input},
                              {"candidates", candidates.size()},
                              {"steps", steps},
                              {"stack", line[culprit].value("stack", "")},
                              {"principal", line[culprit].value("principal", "")}};
        state[StateTable::diagnostics][diagnosis] = diagnosis_record;
        state[StateTable::metrics]["bisections"] = state[StateTable::metrics].value("bisections", 0) + 1;
        state[StateTable::metrics]["bisect_steps"] = state[StateTable::metrics].value("bisect_steps", 0) + steps;
        state[StateTable::metrics]["coalesce_windows"] = state[StateTable::metrics].value("coalesce_windows", 0) + 1;
        event(state, "target_broken", diagnosis_record, "line-" + std::string(line_name));
    }
}
std::vector<std::string> Repository::preparationDomains(StateTransaction const &state, Json const &request) {
    if (state.empty())
        return {};
    auto command = str(request, "command");
    if (command != "stack" && command != "land" && command != "review" && command != "job-complete" &&
        command != "attest" && command != "admin")
        return {};
    std::vector<std::string> paths;
    for (auto const &stack : state.at(StateTable::stacks)) {
        if (str(stack, "status") == "landed" || str(stack, "status") == "abandoned" ||
            str(stack, "status") == "superseded")
            continue;
        for (auto const &key : stack.at("read_set"))
            paths.push_back(key.get<std::string>());
        for (auto const &key : stack.at("write_set"))
            paths.push_back(key.get<std::string>());
    }
    auto args = array(request, "args");
    if (command == "stack" && !args.empty()) {
        auto const &ws = state.record(StateTable::workspaces, args.at(0).get<std::string>());
        if (!ws.is_null()) {
            for (auto const &key : ws.at("reads"))
                paths.push_back(key.get<std::string>());
            for (auto const &change : store_.diff(str(ws.at("base"), "root"), str(ws, "root")))
                paths.push_back(str(change, "path"));
        }
    }
    return domainsOfPaths(paths);
}
void Repository::land(StateTransaction &state, std::string_view id) {
    auto &stack = state[StateTable::stacks][std::string(id)];
    auto status = str(stack, "status");
    if (status == "landed" || status == "abandoned" || status == "superseded" || status == "rejected" ||
        status == "conflicted" || status == "ejected")
        return;
    auto head = snapshot(state, str(stack, "line"));
    auto head_root = str(head, "root");
    auto base_root = str(stack.at("base"), "root");
    auto changes = store_.diff(base_root, str(stack, "root"));
    std::vector<std::string> paths;
    for (auto const &change : changes)
        paths.push_back(str(change, "path"));
    for (auto const &read : stack.at("read_set"))
        paths.push_back(read.get<std::string>());
    auto domains = domainsOfPaths(paths);

    auto candidate = head_root;
    Json conflicts = Json::array();
    std::string route = "fast";
    for (auto const &read : stack.at("read_set")) {
        auto key = read.get<std::string>();
        if (store_.readHash(base_root, key) != store_.readHash(head_root, key))
            route = "rebase";
    }
    for (auto const &change : changes) {
        auto path = str(change, "path");
        auto current = store_.lookup(head_root, path);
        if (current != change.at("old"))
            route = "merge";
        auto merged = axon::mergeFile(store_, change.at("old"), change.at("new"), current);
        if (merged.at("conflict").get<bool>())
            conflicts.push_back({{"path", path}, {"entry", merged.at("entry")}});
        try {
            candidate = store_.set(candidate, path, merged.at("entry"));
        } catch (std::exception const &) {
            conflicts.push_back({{"path", path}, {"entry", change.at("new")}});
        }
    }
    stack["candidate"] = candidate;
    stack["conflicts"] = conflicts;
    stack["route"] = route;
    if (!conflicts.empty()) {
        stack["status"] = "conflicted";
        event(state, "stack_conflicted", {{"stack", id}});
        return;
    }
    auto candidate_changes = store_.diff(head_root, candidate);
    auto subject = axon::hash(candidate_changes.dump());
    stack["review_subject"] = subject;
    auto graph = GraphCache::get(store_, candidate, build_query_);
    auto affected = graph->affected(pathsOf(candidate_changes));
    stack["affected"] = affected;
    auto verdict = decision(state, stack, affected);
    if (route != "fast" || state.at(StateTable::policy).value("fast_path_attestations", false))
        add(verdict["attestations"], "tests");
    for (auto const &workflow : array(state, "workflows"))
        if (str(workflow, "on") == "head_moved" && workflow.value("gate", false))
            add(verdict["attestations"], str(workflow, "kind"));
    stack["decision"] = verdict;
    if (!str(verdict, "denied").empty()) {
        stack["status"] = "rejected";
        stack["reason"] = verdict["denied"];
        return;
    }
    Json requirements = Json::array();
    for (auto const &kind : verdict["attestations"]) {
        auto checks = checkBuilds(state, candidate, affected, true, kind.get<std::string>());
        for (auto const &check : checks)
            requirements.push_back(check);
        // Non-executable attestations remain explicit evidence requirements.
        if (kind != "tests" && includes(decision(state, stack, affected).at("attestations"), kind.get<std::string>())) {
            for (auto const &target : affected) {
                if (std::ranges::any_of(checks, [&target](Json const &check) { return check.at("target") == target; }))
                    continue;
                auto closure = graph->closure(target.get<std::string>());
                requirements.push_back(
                    {{"target", target},
                     {"kind", kind},
                     {"input_hash", closure.at("input_hash")},
                     {"status",
                      attestationStatus(
                          state, target.get<std::string>(), str(closure, "input_hash"), kind.get<std::string>())}});
            }
        }
    }
    if (verdict["review"].get<bool>()) {
        auto groups = verdict["groups"];
        if (groups.empty())
            groups.push_back("");
        for (auto const &group : groups) {
            std::string result = "missing";
            for (auto const &attestation : state[StateTable::attestations]) {
                if (attestation.at("kind") != "reviewed_by" || attestation.at("input_hash") != subject)
                    continue;
                auto signer = str(attestation, "signer");
                if (principalClass(signer) != "human")
                    continue;
                if (group != "" &&
                    !includes(array(state[StateTable::principals][signer], "groups"), group.get<std::string>()))
                    continue;
                result = str(attestation, "result");
            }
            requirements.push_back(
                {{"kind", "reviewed_by"}, {"input_hash", subject}, {"group", group}, {"status", result}});
        }
    }
    stack["requirements"] = requirements;
    for (auto const &requirement : requirements) {
        if (requirement.at("status") != "passed") {
            if (requirement.at("status") == "failed" && requirement.at("kind") != "reviewed_by") {
                auto target = requirement.at("target").get<std::string>();
                auto kind = requirement.at("kind").get<std::string>();
                auto [verdict_str, reason] = blame(state, candidate, head_root, target, kind);
                if (verdict_str == "eject" && (principalClass(str(stack, "principal")) == "agent" ||
                                               state.at(StateTable::policy).value("eject_failing", false))) {
                    stack["status"] = "ejected";
                    stack["reason"] = reason;
                    auto ej = state[StateTable::metrics].value("ejections", 0);
                    state[StateTable::metrics]["ejections"] = ej + 1;
                    event(state,
                          "stack_ejected",
                          {{"stack", id}, {"reason", reason}, {"target", target}},
                          "line-" + str(stack, "line"));
                    return;
                } else {
                    stack["status"] = "blocked";
                    stack["reason"] = reason;
                    return;
                }
            }
            stack["status"] = "blocked";
            stack["reason"] = "waiting for required attestations";
            return;
        }
    }
    auto rate = state.at(StateTable::policy).value("limits", Json::object()).value("landings_per_minute", 0);
    std::size_t recent = 0;
    for (auto const &[line_name, entries] : state[StateTable::lines].items()) {
        (void)line_name;
        for (auto const &entry : entries)
            if (str(entry, "principal") == str(stack, "principal") &&
                entry.at("created").get<std::int64_t>() > axon::now() - 60)
                ++recent;
    }
    if (rate > 0 && recent >= static_cast<std::size_t>(rate)) {
        stack["status"] = "blocked";
        stack["reason"] = "landing rate limit";
        return;
    }
    auto &line = state[StateTable::lines][str(stack, "line")];
    Json landing{{"n", line.size()},
                 {"line", stack.at("line")},
                 {"root", candidate},
                 {"stack", id},
                 {"title", stack.at("title")},
                 {"principal", stack.at("principal")},
                 {"intent", stack.at("intent")},
                 {"route", route},
                 {"paths", pathsOf(candidate_changes)},
                 {"domains", domains},
                 {"created", axon::now()}};
    if (stack.contains("git_author"))
        landing["git_author"] = stack["git_author"];
    landing = seal(landing, "service:sequencer@axon", axon::readFile(directory_ / "sequencer.key"));
    line.push_back(landing);
    stack["status"] = "landed";
    stack["landed"] = landing;
    stack["reason"] = "";
    auto count = state[StateTable::metrics].value(route, 0);
    state[StateTable::metrics][route] = count + 1;
    if (domains.size() > 1) {
        auto cross = state[StateTable::metrics].value("cross_domain", 0);
        state[StateTable::metrics]["cross_domain"] = cross + 1;
    }
    event(state, "stack_landed", landing);
    for (auto const &workflow : array(state, "workflows"))
        if (str(workflow, "on") == "head_moved" && !workflow.value("gate", false))
            (void)checkBuilds(state, candidate, affected, true, str(workflow, "kind"));
}
void Repository::pump(StateTransaction &state) {
    // Submission order is deterministic. A blocked stack does not hold up unrelated work.
    std::vector<std::pair<std::int64_t, std::string>> pending;
    for (auto const &[id, stack] : state[StateTable::stacks].items())
        if (stack.value("queued", false))
            pending.emplace_back(stack.at("created").get<std::int64_t>(), id);
    std::sort(pending.begin(), pending.end());
    for (auto const &[created, id] : pending) {
        (void)created;
        land(state, id);
    }
    std::map<std::string, std::string> projected;
    std::size_t count = 0;
    auto window = state.at(StateTable::policy).value("limits", Json::object()).value("speculative_window", 8);
    for (auto const &[created, id] : pending) {
        (void)created;
        auto &stack = state[StateTable::stacks][id];
        if (str(stack, "status") != "blocked" && str(stack, "status") != "submitted")
            continue;
        if (count++ >= static_cast<std::size_t>(std::clamp(window, 0, 64)))
            break;
        auto line_name = str(stack, "line");
        auto head = str(snapshot(state, line_name), "root");
        auto root = projected.contains(line_name) ? projected.at(line_name) : head;
        auto before = root;
        bool conflict = false;
        for (auto const &change : store_.diff(str(stack.at("base"), "root"), str(stack, "root"))) {
            auto path = str(change, "path");
            auto merged = axon::mergeFile(store_, change.at("old"), change.at("new"), store_.lookup(root, path));
            if (merged.at("conflict").get<bool>()) {
                conflict = true;
                break;
            }
            try {
                root = store_.set(root, path, merged.at("entry"));
            } catch (std::exception const &) {
                conflict = true;
                break;
            }
        }
        if (conflict)
            continue;
        auto graph = GraphCache::get(store_, root, build_query_);
        auto affected = graph->affected(pathsOf(store_.diff(before, root)));
        auto verdict = decision(state, stack, affected);
        if (!str(verdict, "denied").empty())
            continue;
        projected[line_name] = root;
        if (before == head)
            continue; // The ordinary landing path already requested this candidate.
        if (str(stack, "speculative_root") != root) {
            stack["speculative_root"] = root;
            state[StateTable::metrics]["speculative_candidates"] =
                state[StateTable::metrics].value("speculative_candidates", 0) + 1;
        }
        auto kinds = verdict.at("attestations");
        add(kinds, "tests");
        for (auto const &workflow : array(state, "workflows"))
            if (workflow.value("gate", false))
                add(kinds, str(workflow, "kind"));
        for (auto const &kind : kinds)
            (void)checkBuilds(state, root, affected, true, kind.get<std::string>());
    }
}
Json Repository::execute(StateTransaction &state,
                         std::string_view principal,
                         Json const &request,
                         bool local_executor) {
    auto command = str(request, "command");
    auto args = strings(array(request, "args"));
    auto options = request.value("options", Json::object());
    auto arg = [&args](std::size_t i) -> std::string {
        require(i < args.size(), "missing command argument");
        return args[i];
    };
    auto flag = [&options](std::string_view name) -> bool {
        return options.value(std::string(name), "false") == "true";
    };
    if (command == "whoami")
        return Json{{"principal", principal}, {"identity", state[StateTable::principals][std::string(principal)]}};
    if (command == "fork")
        return forkWorkspace(state, principal, options);
    if (command == "lines")
        return state[StateTable::lines];
    if (command == "line") {
        require(arg(0) == "create", "usage: line create NAME --from line@N");
        require(admin(state, principal), "admin required");
        auto name = arg(1);
        require(!name.empty() &&
                    name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.") ==
                        std::string::npos,
                "invalid line name");
        require(!state[StateTable::lines].contains(name), "line already exists");
        auto base = snapshot(state, str(options, "from", "trunk"));
        state[StateTable::lines][name] =
            Json::array({Json{{"n", 0}, {"root", base["root"]}, {"created", axon::now()}, {"from", base}}});
        return state[StateTable::lines][name];
    }
    if (command == "ws") {
        auto sub = args.empty() ? "list" : arg(0);
        if (sub == "list" || sub == "ls") {
            Json result = Json::array();
            for (auto const &[id, ws] : state[StateTable::workspaces].items()) {
                (void)id;
                if (ws.at("owner") == principal || admin(state, principal))
                    result.push_back(ws);
            }
            return result;
        }
        auto id = arg(1);
        auto &ws = workspace(state, id, principal);
        if (sub == "drop") {
            state.erase(StateTable::workspaces, id);
            return Json{{"dropped", id}};
        }
        if (sub == "reads")
            return ws.at("reads");
        auto head = snapshot(state, str(ws.at("base"), "line"));
        Json stale = Json::array();
        for (auto const &read : ws.at("reads")) {
            auto key = read.get<std::string>();
            if (store_.readHash(str(ws.at("base"), "root"), key) != store_.readHash(str(head, "root"), key))
                stale.push_back(key);
        }
        if (sub == "rebase") {
            auto root = str(head, "root");
            for (auto const &change : store_.diff(str(ws.at("base"), "root"), str(ws, "root"))) {
                auto merged = axon::mergeFile(
                    store_, change.at("old"), change.at("new"), store_.lookup(root, str(change, "path")));
                require(!merged.at("conflict").get<bool>(),
                        "workspace rebase has conflicts; submit and resolve the stack");
                root = store_.set(root, str(change, "path"), merged.at("entry"));
            }
            ws["base"] = head;
            ws["root"] = root;
            return Json{{"workspace", ws}, {"stale", stale}};
        }
        require(sub == "status", "unknown ws command");
        return Json{{"workspace", ws},
                    {"head", head},
                    {"stale", stale},
                    {"changes", store_.diff(str(ws.at("base"), "root"), str(ws, "root"))}};
    }
    if (command == "symbol") {
        auto &ws = workspace(state, arg(0), principal);
        auto path = axon::cleanPath(arg(1));
        require(path.find('#') == std::string::npos, "symbol paths cannot contain #");
        auto entry = store_.lookup(str(ws, "root"), path);
        require(!entry.is_null() && entry.at("kind") == "file", "symbol source does not exist");
        auto result = readSymbol(store_.blob(str(entry, "hash")), arg(2));
        add(ws["reads"], "symbol:" + path + "#" + arg(2));
        return result;
    }
    if (command == "fs") {
        auto &ws = workspace(state, arg(0), principal);
        auto before = ws.at("root");
        auto result = filesystemRequest(store_, ws, request);
        if (ws.at("root") != before)
            event(state, "workspace_changed", {{"workspace", ws.at("id")}, {"root", ws.at("root")}});
        return result;
    }
    if (command == "cat" || command == "ls" || command == "write" || command == "rm" || command == "mv") {
        auto &ws = workspace(state, arg(0), principal);
        auto root = str(ws, "root");
        auto path = axon::cleanPath(args.size() > 1 ? args[1] : "", command == "ls");
        if (command == "ls") {
            add(ws["reads"], path + "/");
            auto entry = store_.lookup(root, path);
            if (entry.is_null() || entry.at("kind") != "dir")
                return Json{{"error", "directory does not exist"}};
            return store_.list(root, path);
        }
        add(ws["reads"], path);
        if (command == "cat") {
            auto entry = store_.lookup(root, path);
            if (entry.is_null() || entry.at("kind") == "dir")
                return Json{{"error", "file does not exist"}};
            if (request.value("metadata_only", false))
                return Json{{"blob", entry.at("hash")}};
            return Json{{"bytes", axon::hex(store_.blob(str(entry, "hash")))}};
        }
        Json operation{{"op", command}, {"path", path}};
        if (command == "write") {
            auto bytes = axon::unhex(str(request, "input"));
            Json entry{{"kind", flag("link") ? "link" : "file"},
                       {"exec", flag("x")},
                       {"hash", store_.putBlob(bytes)},
                       {"size", bytes.size()}};
            root = store_.set(root, path, entry);
            operation["entry"] = entry;
        } else if (command == "rm") {
            require(!store_.lookup(root, path).is_null(), "path does not exist");
            root = store_.set(root, path, nullptr);
        } else {
            auto destination = axon::cleanPath(arg(2));
            require(destination != path && !destination.starts_with(path + "/"), "cannot move path into itself");
            auto entry = store_.lookup(root, path);
            require(!entry.is_null(), "source does not exist");
            require(store_.lookup(root, destination).is_null(), "destination exists");
            add(ws["reads"], destination);
            root = store_.set(root, path, nullptr);
            root = store_.set(root, destination, entry);
            operation["destination"] = destination;
        }
        operation["created"] = axon::now();
        operation["id"] = store_.put(operation.dump());
        ws["drafts"].push_back(operation);
        ws["root"] = root;
        event(state, "workspace_changed", {{"workspace", ws["id"]}, {"root", root}});
        return operation;
    }
    if (command == "snapshot-files") {
        auto base = snapshot(state, arg(0));
        auto files = store_.files(str(base, "root"));
        for (auto &[path, entry] : files.items()) {
            (void)path;
            entry["bytes"] = axon::hex(store_.blob(str(entry, "hash")));
        }
        return files;
    }
    if (command == "git-stage") {
        auto imported = str(options, "imported") == "true";
        require(!imported || admin(state, principal), "Git history import requires admin");
        auto commit = str(request, "git_commit");
        auto line = str(options, "line", "trunk");
        for (auto const &[id, stack] : state[StateTable::stacks].items())
            if (str(stack, "git_commit") == commit && str(stack, "line") == line && str(stack, "status") == "landed")
                return Json{{"skipped", id}};
        auto ws = forkWorkspace(state, principal, {{"from", line}});
        auto root = store_.empty();
        for (auto const &[path, file] : request.at("files").items()) {
            auto normalized = axon::cleanPath(path);
            auto bytes = axon::unhex(str(file, "bytes"));
            auto kind = str(file, "kind");
            require(kind == "file" || kind == "link", "invalid git entry kind");
            root = store_.set(root,
                              normalized,
                              {{"kind", kind},
                               {"exec", file.value("exec", false)},
                               {"hash", store_.putBlob(bytes)},
                               {"size", bytes.size()}});
        }
        if (root == str(ws, "root")) {
            state.erase(StateTable::workspaces, str(ws, "id"));
            return Json{{"skipped", commit}};
        }
        ws["root"] = root;
        ws["git_commit"] = commit;
        if (imported && request.contains("git_author")) {
            auto author = str(request, "git_author");
            require(author.find('\0') == std::string::npos &&
                        std::regex_match(author, std::regex("[^<>\r\n]* <[^<>\r\n]*> -?[0-9]+ [+-][0-9]{4}")),
                    "invalid Git author");
            ws["git_author"] = author;
        }
        ws["imported"] = imported;
        if (!imported)
            add(ws["reads"], "**");
        state.edit(StateTable::workspaces, str(ws, "id")) = ws;
        return ws;
    }
    if (command == "get") {
        auto base = snapshot(state, arg(0));
        auto path = axon::cleanPath(arg(1), true);
        auto entry = store_.lookup(str(base, "root"), path);
        require(!entry.is_null(), "path does not exist");
        if (entry.at("kind") == "dir")
            return store_.list(str(base, "root"), path);
        if (request.value("metadata_only", false))
            return Json{{"blob", entry.at("hash")}};
        return Json{{"bytes", axon::hex(store_.blob(str(entry, "hash")))}};
    }
    if (command == "stack") {
        auto ws = workspace(state, arg(0), principal);
        auto changes = store_.diff(str(ws.at("base"), "root"), str(ws, "root"));
        require(!changes.empty(), "workspace has no changes");
        require(!str(options, "title").empty(), "stack requires --title");
        auto intent = str(options, "intent", "freeform");
        require(includes(Json{"rename", "fix", "refactor", "feature", "test", "dep_bump", "freeform"}, intent),
                "unknown intent");
        auto reads = ws.at("reads");
        auto writes = pathsOf(changes);
        if (state.at(StateTable::policy).value("session_scoped_reads", false) && !str(ws, "session").empty()) {
            for (auto const &[other_id, other] : state[StateTable::workspaces].items()) {
                (void)other_id;
                if (other.at("owner") == principal && str(other, "session") == str(ws, "session"))
                    for (auto const &read : other.at("reads"))
                        add(reads, read.get<std::string>());
            }
        }
        for (auto const &write : writes)
            add(reads, write.get<std::string>());
        Json assumed = Json::array();
        std::istringstream assumptions(str(options, "assume-unrelated"));
        std::string key;
        while (std::getline(assumptions, key, ',')) {
            require(!includes(writes, key), "cannot exclude a write from the read set");
            add(assumed, key);
            reads.erase(std::remove(reads.begin(), reads.end(), Json(key)), reads.end());
        }
        Json stack{{"workspace", ws["id"]},
                   {"principal", principal},
                   {"base", ws["base"]},
                   {"root", ws["root"]},
                   {"line", ws["base"]["line"]},
                   {"title", str(options, "title")},
                   {"intent", intent},
                   {"created", axon::now()},
                   {"read_set", reads},
                   {"write_set", writes},
                   {"assume_unrelated", assumed},
                   {"policy_class", str(options, "class")},
                   {"review_subject", axon::hash(changes.dump())},
                   {"status", "submitted"},
                   {"queued", flag("land") || flag("wait")},
                   {"nonce", axon::randomHex()}};
        Json labels = Json::array();
        std::istringstream label_stream(str(options, "labels"));
        std::string label;
        while (std::getline(label_stream, label, ','))
            add(labels, label);
        stack["labels"] = labels;
        stack["intent_note"] = str(options, "note");
        stack["imported"] = ws.value("imported", false);
        if (ws.contains("git_commit"))
            stack["git_commit"] = ws["git_commit"];
        if (ws.contains("git_author"))
            stack["git_author"] = ws["git_author"];
        // The signed submission is immutable; status and planning fields live outside it.
        stack = seal(stack, "service:sequencer@axon", axon::readFile(directory_ / "sequencer.key"));
        auto id = str(stack, "id");
        auto submission = stack;
        stack.erase("signature");
        stack.erase("key");
        stack.erase("signer");
        stack["submission"] = submission;
        if (!str(options, "supersedes").empty()) {
            auto previous = stackId(state, str(options, "supersedes"));
            auto &old = state[StateTable::stacks][previous];
            require(old.at("principal") == principal || admin(state, principal), "not stack owner");
            require(str(old, "status") != "landed", "cannot supersede landed stack");
            old["status"] = "superseded";
            old["superseded_by"] = id;
        }
        state[StateTable::stacks][id] = stack;
        event(state, "stack_submitted", {{"stack", id}});
        if (stack["queued"].get<bool>())
            pump(state);
        return state[StateTable::stacks][id];
    }
    if (command == "status" || command == "queue") {
        pump(state);
        if (command == "status" && !args.empty())
            return state[StateTable::stacks][stackId(state, arg(0))];
        Json result = Json::array();
        for (auto const &[id, stack] : state[StateTable::stacks].items()) {
            (void)id;
            if (command == "queue" && (!stack.value("queued", false) ||
                                       (str(stack, "status") != "blocked" && str(stack, "status") != "submitted")))
                continue;
            if (command == "status" && !flag("all") && stack.at("principal") != principal)
                continue;
            if (!str(options, "status").empty() && str(stack, "status") != str(options, "status"))
                continue;
            result.push_back(stack);
        }
        return result;
    }
    if (command == "land" || command == "review" || command == "abandon" || command == "resolve" || command == "diff") {
        auto id = stackId(state, arg(0));
        auto &stack = state[StateTable::stacks][id];
        if (command == "diff") {
            auto changes = store_.diff(str(stack.at("base"), "root"), str(stack, "root"));
            return flag("json") ? changes : Json{{"bytes", axon::hex(axon::unifiedDiff(store_, changes))}};
        }
        if (command == "review") {
            require(principalClass(principal) == "human", "only human principals may review");
            require(str(request, "review_subject") == str(stack, "review_subject"),
                    "review subject changed; inspect the stack again");
            auto claim = request.at("attestation");
            require(str(claim, "type") == "axon-attestation-1" && str(claim, "target") == "review:stack" &&
                        str(claim, "input_hash") == str(stack, "review_subject") &&
                        str(claim, "kind") == "reviewed_by" &&
                        str(claim, "result") == (flag("reject") ? "failed" : "passed") && claim.at("expires") == 0 &&
                        str(claim, "detail") == str(options, "m"),
                    "review statement does not match request");
            state[StateTable::attestations].push_back(claim);
            event(state, "review", claim);
            pump(state);
            return state[StateTable::stacks][id];
        }
        require(stack.at("principal") == principal || admin(state, principal), "not stack owner");
        if (command == "abandon") {
            require(str(stack, "status") != "landed", "already landed");
            stack["status"] = "abandoned";
            return stack;
        }
        if (command == "land") {
            stack["queued"] = true;
            pump(state);
            return state[StateTable::stacks][id];
        }
        require(str(stack, "status") == "conflicted", "stack is not conflicted");
        auto ws = forkWorkspace(state, principal, {{"from", stack["line"]}});
        auto root = str(ws, "root");
        for (auto const &change : store_.diff(str(stack.at("base"), "root"), str(stack, "root"))) {
            auto path = str(change, "path");
            auto merged = axon::mergeFile(store_, change.at("old"), change.at("new"), store_.lookup(root, path));
            root = store_.set(root, path, merged.at("entry"));
            add(ws["reads"], path);
        }
        ws["root"] = root;
        state.edit(StateTable::workspaces, str(ws, "id")) = ws;
        return ws;
    }
    if (command == "log" || command == "audit") {
        auto line = str(options, "line", "trunk");
        require(state[StateTable::lines].contains(line), "unknown line");
        auto path = command == "audit" ? arg(0) : str(options, "path");
        Json result = Json::array();
        for (auto const &entry : state[StateTable::lines][line])
            if (path.empty() || includes(array(entry, "paths"), path))
                result.push_back(entry);
        if (options.contains("limit")) {
            auto limit = std::stoull(str(options, "limit"));
            if (result.size() > limit) {
                Json limited = Json::array();
                for (std::size_t i = result.size() - limit; i < result.size(); ++i)
                    limited.push_back(result[i]);
                result = std::move(limited);
            }
        }
        return result;
    }
    if (command == "workflows") {
        return state.value(StateTable::workflows,
                           Json::array({{{"name", "tests"}, {"on", "head_moved"}, {"kind", "tests"}, {"gate", true}}}));
    }
    if (command == "queue") {
        auto line_name = str(options, "line", "trunk");
        Json out = Json::array();
        for (auto const &[st_id, st] : state[StateTable::stacks].items()) {
            if (str(st, "line") == line_name &&
                (str(st, "status") == "queued" || str(st, "status") == "blocked" || str(st, "status") == "waiting")) {
                out.push_back({{"stack", st_id},
                               {"line", line_name},
                               {"queued", st.value("created", 0)},
                               {"status", str(st, "status")},
                               {"route", st.value("route", "fast")}});
            }
        }
        return out;
    }
    if (command == "targets" || command == "closure" || command == "affected" || command == "materialize" ||
        command == "green") {
        auto base = snapshot(state, command == "green" && !args.empty() ? args[0] : str(options, "at", "trunk"));
        auto graph = GraphCache::get(store_, str(base, "root"), build_query_);
        if (command == "targets")
            return graph->targets();
        if (command == "affected")
            return graph->affected(args);
        if (command == "closure" || command == "materialize") {
            auto closure = graph->closure(arg(0));
            if (command == "materialize") {
                Json contents = Json::object();
                for (auto const &[path, entry] : closure["files"].items())
                    contents[path] = axon::hex(store_.blob(str(entry, "hash")));
                closure["contents"] = contents;
            }
            return closure;
        }
        Json targets = Json::array();
        for (auto const &[name, target] : graph->targets().items())
            if (!str(target.at("def"), "cmd").empty())
                targets.push_back(name);
        Json kinds = Json::array({"tests"});
        for (auto const &workflow : array(state, "workflows"))
            add(kinds, str(workflow, "kind"));
        Json checks = Json::array();
        for (auto const &kind : kinds)
            for (auto const &check :
                 checkBuilds(state, str(base, "root"), targets, flag("request"), kind.get<std::string>()))
                checks.push_back(check);
        bool green = true;
        for (auto const &check : checks)
            green &= check.at("status") == "passed";
        return Json{{"snapshot", base}, {"green", green}, {"requirements", checks}};
    }
    if (command == "job-claim") {
        require(principalClass(principal) != "agent", "agents may not execute CI jobs");
        for (auto &[id, job] : state[StateTable::jobs].items()) {
            (void)id;
            if (str(job, "status") == "done" || job.value("lease_until", std::int64_t{0}) > axon::now())
                continue;
            job["worker"] = principal;
            job["lease_until"] = axon::now() + 120;
            job["lease"] = axon::randomHex();
            job["status"] = "running";
            auto result = job;
            Json contents = Json::object();
            if (!request.value("omit_contents", false))
                for (auto const &[path, entry] : job.at("files").items())
                    contents[path] = axon::hex(store_.blob(str(entry, "hash")));
            result["contents"] = contents;
            return result;
        }
        return nullptr;
    }
    if (command == "job-complete") {
        auto id = arg(0);
        require(state[StateTable::jobs].contains(id), "unknown job");
        auto &job = state[StateTable::jobs][id];
        require(job.at("worker") == principal && job.at("lease") == str(request, "lease") &&
                    job.at("lease_until").get<std::int64_t>() >= axon::now(),
                "invalid executor lease");
        require(str(job, "status") == "running", "job is already complete");
        auto result = str(options, "result");
        require(result == "passed" || result == "failed", "invalid execution result");
        auto definition = job.at("definition");
        Json claim{
            {"target", job.at("target")},
            {"input_hash", job.at("input_hash")},
            {"kind", job.at("kind")},
            {"result", result},
            {"signer", principal},
            {"created", axon::now()},
            {"nonce", axon::randomHex()},
            {"expires", str(definition, "ttl").empty() ? 0 : axon::now() + parseDuration(str(definition, "ttl"), 0)},
            {"evidence_ref", store_.putBlob(axon::unhex(str(request, "input")))}};
        if (!local_executor) {
            require(request.contains("completion"), "signed executor completion required");
            auto completion = request.at("completion");
            require(str(completion, "type") == "axon-executor-completion-1" && completion.at("job") == id &&
                        completion.at("lease") == job.at("lease") && completion.at("result") == result &&
                        completion.at("evidence_hash") == axon::hash(axon::unhex(str(request, "input"))),
                    "executor completion does not match job or evidence");
            claim["completion"] = completion;
        } else {
            claim = seal(claim, principal, axon::readFile(directory_ / "sequencer.key"));
        }
        if (!claim.contains("id"))
            claim["id"] = axon::hash(claim.dump());
        state[StateTable::attestations].push_back(claim);
        job["status"] = "done";
        event(state, "attestation", claim);
        pump(state);
        for (auto const &[line_name, history] : state[StateTable::lines].items()) {
            (void)history;
            coalesceAndBisect(state, line_name);
        }
        return claim;
    }
    if (command == "attest") {
        require(principalClass(principal) != "agent", "agents may not attest CI results");
        auto result = str(options, "result");
        require(result == "passed" || result == "failed", "result must be passed or failed");
        auto kind = str(options, "kind");
        require(!kind.empty() && kind != "reviewed_by", "use review for review attestations");
        require(str(options, "input").size() == 64 && !str(options, "target").empty(),
                "target and input hash required");
        auto claim = request.at("attestation");
        require(str(claim, "type") == "axon-attestation-1" && str(claim, "target") == str(options, "target") &&
                    str(claim, "input_hash") == str(options, "input") && str(claim, "kind") == kind &&
                    str(claim, "result") == result &&
                    claim.at("expires") == (str(options, "ttl").empty() ? 0
                                                                        : claim.at("created").get<std::int64_t>() +
                                                                              parseDuration(str(options, "ttl"), 0)),
                "attestation statement does not match request");
        state[StateTable::attestations].push_back(claim);
        event(state, "attestation", claim);
        pump(state);
        for (auto const &[line_name, history] : state[StateTable::lines].items()) {
            (void)history;
            coalesceAndBisect(state, line_name);
        }
        return claim;
    }
    if (command == "events" || command == "subscribe") {
        auto part = !args.empty() ? args[0] : str(options, "partition");
        auto line_name = str(options, "line");
        std::vector<std::string> path_globs;
        if (options.contains("paths")) {
            std::istringstream stream(str(options, "paths"));
            std::string g;
            while (std::getline(stream, g, ',')) {
                if (!g.empty())
                    path_globs.push_back(g);
            }
        }
        auto grp = str(options, "group");
        if (options.contains("commit")) {
            auto off = std::stoull(str(options, "commit"));
            state[StateTable::consumer_offsets][grp + "/" + (part.empty() ? "all" : part)] = off;
            return Json{{"ok", true}, {"committed", off}};
        }
        std::size_t offset = 0;
        if (options.contains("from")) {
            offset = std::stoull(str(options, "from"));
        } else if (!grp.empty()) {
            offset = state[StateTable::consumer_offsets].value(grp + "/" + (part.empty() ? "all" : part), 0);
        }
        return filterEvents(state, offset, part, line_name, path_globs);
    }
    if (command == "metrics")
        return state[StateTable::metrics];
    if (command == "agent-key") {
        require(principalClass(principal) == "human", "only humans may issue agent keys");
        auto name = arg(0);
        require(!name.empty() &&
                    name.find_first_not_of("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-") ==
                        std::string::npos,
                "invalid agent name");
        auto id = "agent:" + name + "@" + std::string(principal.substr(6));
        auto key = str(request, "public_key");
        require(key.size() == 64, "invalid public key");
        (void)axon::unhex(key);
        auto binding = request.at("binding");
        auto expires = binding.at("expires").get<std::int64_t>();
        require(str(binding, "type") == "axon-agent-binding-1" && str(binding, "principal") == id &&
                    str(binding, "public_key") == key && str(binding, "owner") == principal &&
                    expires == binding.at("created").get<std::int64_t>() + parseDuration(str(options, "ttl"), 86400),
                "agent binding does not match request");
        state[StateTable::principals][id] = {
            {"key", key}, {"groups", Json::array()}, {"expires", expires}, {"owner", principal}, {"binding", binding}};
        return Json{{"principal", id}, {"binding", binding}};
    }
    if (command == "admin") {
        require(admin(state, principal), "admin required");
        auto sub = arg(0);
        if (sub == "workflows") {
            if (request.contains("input")) {
                auto wfs = Json::parse(axon::unhex(str(request, "input")));
                require(wfs.is_array(), "workflows must be an array");
                std::set<std::string> names;
                for (auto const &workflow : wfs) {
                    require(workflow.is_object(), "workflow must be an object");
                    for (auto const &[key, value] : workflow.items()) {
                        (void)value;
                        require(key == "name" || key == "on" || key == "kind" || key == "gate",
                                "unknown workflow field");
                    }
                    require(!str(workflow, "name").empty() && names.insert(str(workflow, "name")).second,
                            "workflow names must be nonempty and unique");
                    require(str(workflow, "on") == "head_moved" || str(workflow, "on") == "workspace_changed" ||
                                str(workflow, "on") == "stack_submitted",
                            "unknown workflow event");
                    require(!workflow.value("gate", false) || str(workflow, "on") == "head_moved",
                            "only head_moved workflows can gate landing");
                    require(!str(workflow, "kind").empty() && str(workflow, "kind") != "reviewed_by",
                            "workflow needs a CI kind");
                    require(!workflow.contains("gate") || workflow.at("gate").is_boolean(),
                            "workflow gate must be boolean");
                }
                state[StateTable::workflows] = wfs;
                pump(state);
            }
            return state.value(
                "workflows",
                Json::array({{{"name", "tests"}, {"on", "head_moved"}, {"kind", "tests"}, {"gate", true}}}));
        }

        if (sub == "policy") {
            if (request.contains("input")) {
                auto policy = Json::parse(axon::unhex(str(request, "input")));
                axon::validatePolicy(policy);
                state[StateTable::policy] = policy;
                pump(state);
            }
            return state[StateTable::policy];
        }
        if (sub == "add") {
            auto id = arg(1);
            (void)principalClass(id);
            auto key = str(options, "key");
            require(key.size() == 64, "--key requires public key hex");
            (void)axon::unhex(key);
            Json groups = Json::array();
            std::istringstream stream(str(options, "groups"));
            std::string group;
            while (std::getline(stream, group, ','))
                groups.push_back(group);
            state[StateTable::principals][id] = {{"key", key}, {"groups", groups}, {"expires", 0}};
            return state[StateTable::principals][id];
        }
        if (sub == "prune") {
            auto keep_text = str(options, "keep", "100");
            std::size_t end = 0;
            auto keep = std::stoll(keep_text, &end);
            require(end == keep_text.size() && keep >= 1, "retention keep must be positive");
            auto age = parseDuration(str(options, "age", "30d"), 2592000);
            return pruneMetadata(state, axon::now() - age, static_cast<std::size_t>(keep), flag("dry-run"));
        }
        if (sub == "compact") {
            auto &nonces = state[StateTable::nonces];
            for (auto it = nonces.begin(); it != nonces.end();) {
                if (it.value().get<std::int64_t>() < axon::now() - 300)
                    it = nonces.erase(it);
                else
                    ++it;
            }
            return Json{{"compacted", true}};
        }
        if (sub == "gc") {
            // All history, workspaces and attestations remain roots. Only unreachable
            // CAS objects older than the grace period can be collected.
            std::set<std::string> marked;
            auto visit = [this, &marked](auto const &self, Json const &value) -> void {
                if (value.is_string()) {
                    auto text = value.get<std::string>();
                    if (text.size() != 64 || text.find_first_not_of("0123456789abcdef") != std::string::npos ||
                        marked.contains(text))
                        return;
                    marked.insert(text);
                    try {
                        auto bytes = store_.get(text);
                        auto object = Json::parse(bytes, nullptr, false);
                        if (!object.is_discarded())
                            self(self, object);
                    } catch (std::exception const &) {
                    }
                } else if (value.is_structured())
                    for (auto const &child : value)
                        self(self, child);
            };
            visit(visit, state.json());
            std::size_t objects = 0;
            std::uintmax_t bytes = 0;
            for (auto const &entry : std::filesystem::recursive_directory_iterator(store_.directory())) {
                if (!entry.is_regular_file())
                    continue;
                auto id = entry.path().parent_path().filename().string() + entry.path().filename().string();
                if (marked.contains(id) ||
                    std::filesystem::file_time_type::clock::now() - entry.last_write_time() < std::chrono::hours(24))
                    continue;
                ++objects;
                bytes += entry.file_size();
                if (!flag("dry-run"))
                    std::filesystem::remove(entry.path());
            }
            return Json{{"objects", objects}, {"bytes", bytes}, {"dry_run", flag("dry-run")}};
        }
        throw std::runtime_error("unknown admin command");
    }
    throw std::runtime_error("unknown command: " + command);
}
} // namespace axon
