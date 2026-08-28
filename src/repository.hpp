#pragma once
#include "line.hpp"
#include "storage.hpp"

#include <expected>
#include <mutex>
#include <shared_mutex>
#include <stop_token>
#include <string>
#include <string_view>

namespace axon {
class Repository {
public:
    explicit Repository(Path const &directory, bool execute_builds = true, bool no_sync = false);
    void initialize(std::string_view admin, std::string_view key);
    [[nodiscard]] std::expected<Json, std::string> request(Json const &envelope);
    [[nodiscard]] Json inspect() const;
    [[nodiscard]] Json identity(std::string_view principal) const;
    void runExecutor(std::stop_token stop);
    [[nodiscard]] Store const &store() const {
        return store_;
    }
    [[nodiscard]] Store &store() {
        return store_;
    }
    [[nodiscard]] bool authReads() const {
        return auth_reads_;
    }
    void setAuthReads(bool auth) {
        auth_reads_ = auth;
    }
    void setBuildQuery(std::string_view query) {
        build_query_ = query;
    }
    [[nodiscard]] std::string const &buildQuery() const {
        return build_query_;
    }
    [[nodiscard]] std::string metricsPrometheus() const;
    [[nodiscard]] Json eventsSince(std::size_t offset,
                                   std::string_view partition = "",
                                   std::string_view line = "",
                                   std::vector<std::string> const &paths = {}) const;

private:
    [[nodiscard]] static Json filterEvents(StateTransaction const &state,
                                           std::size_t offset,
                                           std::string_view partition,
                                           std::string_view line,
                                           std::vector<std::string> const &paths);
    [[nodiscard]] Json
    execute(StateTransaction &state, std::string_view principal, Json const &request, bool local_executor = false);
    [[nodiscard]] Json snapshot(StateTransaction const &state, std::string_view position) const;
    [[nodiscard]] Json &workspace(StateTransaction &state, std::string_view id, std::string_view principal);
    [[nodiscard]] std::string stackId(StateTransaction const &state, std::string_view prefix) const;
    [[nodiscard]] Json forkWorkspace(StateTransaction &state, std::string_view principal, Json const &source);
    [[nodiscard]] std::vector<std::string> preparationDomains(StateTransaction const &state, Json const &request);
    void land(StateTransaction &state, std::string_view id);
    void pump(StateTransaction &state);
    void event(StateTransaction &state, std::string_view kind, Json const &data, std::string_view partition = "");
    [[nodiscard]] Json checkBuilds(
        StateTransaction &state, std::string_view root, Json const &targets, bool run, std::string_view kind = "tests");
    [[nodiscard]] Json decision(StateTransaction const &state, Json const &stack, Json const &affected) const;
    [[nodiscard]] std::pair<std::string, std::string> blame(StateTransaction &state,
                                                            std::string_view candidate,
                                                            std::string_view head_root,
                                                            std::string_view target,
                                                            std::string_view kind);
    void coalesceAndBisect(StateTransaction &state, std::string_view line);
    Database database_;
    Store store_;
    Path directory_;
    bool execute_builds_;
    mutable std::shared_mutex maintenance_mutex_;
    DomainLockManager domain_locks_;
    bool auth_reads_ = false;
    std::string build_query_;
};
[[nodiscard]] Json signedRequest(Json const &payload, std::string_view principal, std::string_view seed);
} // namespace axon
