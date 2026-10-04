#include "bench.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <iomanip>
#include <mutex>
#include <random>
#include <sstream>
#include <thread>

namespace axon {

void BenchResult::print(std::ostream &os) const {
    double rate = elapsed_secs > 0 ? static_cast<double>(landings) / elapsed_secs : 0.0;
    os << "landings      " << landings << " in " << std::fixed << std::setprecision(1) << elapsed_secs << "s  ("
       << static_cast<std::int64_t>(rate) << "/s total)\n";
    os << "paths         fast " << fast << "  rebase " << rebase << "  merge " << merge << "  conflicted " << conflicts
       << "  other " << other << "\n";
    os << "cross-domain  " << cross_domain << " (2PC)\n";
    auto format_us = [](std::int64_t us) -> std::string {
        if (us < 1000)
            return std::to_string(us) + "µs";
        return std::to_string(us / 1000) + "ms";
    };
    os << "land latency  p50 " << format_us(p50_us) << "  p90 " << format_us(p90_us) << "  p99 " << format_us(p99_us)
       << "  max " << format_us(max_us) << "\n";
    os << "busiest domain " << static_cast<std::int64_t>(busiest_domain_rate) << " landings/s\n";
}

BenchResult runBench(BenchConfig const &cfg, std::ostream &progress) {
    (void)progress;
    auto work_dir = cfg.dir.empty() ? Path(std::filesystem::temp_directory_path() / ("axon-bench-" + axon::randomHex()))
                                    : Path(cfg.dir);
    bool cleanup_dir = cfg.dir.empty();
    std::filesystem::create_directories(work_dir);

    BenchResult result;
    try {
        Repository repo(work_dir, false, !cfg.sync);
        auto admin_seed = axon::randomHex(32);
        auto admin_key = axon::publicKey(admin_seed);
        repo.initialize("human:bench", admin_key);

        // Set permissive policy
        (void)repo.request(
            signedRequest({{"command", "admin"}, {"args", {"policy"}}, {"input", axon::hex("{\"rules\":[]}")}},
                          "human:bench",
                          admin_seed));

        // Seed repository with initial files
        auto fork_res = repo.request(signedRequest({{"command", "fork"}}, "human:bench", admin_seed));
        if (!fork_res)
            throw std::runtime_error("failed to fork seed workspace: " + fork_res.error());
        auto seed_ws = fork_res->at("id").get<std::string>();

        for (int d = 0; d < cfg.domains; ++d) {
            for (int f = 0; f < cfg.files; ++f) {
                char pbuf[64];
                std::snprintf(pbuf, sizeof(pbuf), "d%02d/pkg%02d/f%04d.txt", d, f % 16, f);
                std::string content = "line one\nfile " + std::string(pbuf) + "\nline three\n";
                (void)repo.request(
                    signedRequest({{"command", "write"}, {"args", {seed_ws, pbuf, "-"}}, {"input", axon::hex(content)}},
                                  "human:bench",
                                  admin_seed));
            }
        }

        auto seed_land = repo.request(signedRequest(
            {{"command", "stack"}, {"args", {seed_ws}}, {"options", {{"title", "seed"}, {"land", "true"}}}},
            "human:bench",
            admin_seed));
        if (!seed_land || seed_land->value("status", "") != "landed")
            throw std::runtime_error("failed to land seed");

        // Prepare agent keys
        struct AgentInfo {
            std::string id;
            std::string seed;
        };
        std::vector<AgentInfo> agents;
        agents.reserve(static_cast<std::size_t>(cfg.agents));
        for (int a = 0; a < cfg.agents; ++a) {
            auto a_name = "a" + std::to_string(a);
            auto a_seed = axon::randomHex(32);
            auto ak_res = repo.request(
                signedRequest({{"command", "agent-key"}, {"args", {a_name}}, {"public_key", axon::publicKey(a_seed)}},
                              "human:bench",
                              admin_seed));
            if (!ak_res)
                throw std::runtime_error("failed agent-key: " + ak_res.error());
            agents.push_back({ak_res->at("principal").get<std::string>(), a_seed});
        }

        std::atomic<bool> stop{false};
        std::atomic<std::int64_t> landings{0};
        std::atomic<std::int64_t> fast{0};
        std::atomic<std::int64_t> rebase{0};
        std::atomic<std::int64_t> merge{0};
        std::atomic<std::int64_t> conflicts{0};
        std::atomic<std::int64_t> other{0};
        std::atomic<std::int64_t> cross_domain{0};

        std::mutex lats_mutex;
        std::vector<std::int64_t> lats;
        std::unordered_map<std::string, int> domain_counts;

        auto start = std::chrono::steady_clock::now();
        std::vector<std::thread> threads;
        threads.reserve(static_cast<std::size_t>(cfg.agents));

        for (int a = 0; a < cfg.agents; ++a) {
            threads.emplace_back([a,
                                  &cfg,
                                  &agents,
                                  &repo,
                                  &stop,
                                  &landings,
                                  &fast,
                                  &rebase,
                                  &merge,
                                  &conflicts,
                                  &other,
                                  &cross_domain,
                                  &lats_mutex,
                                  &lats,
                                  &domain_counts]() {
                auto const &agent = agents[static_cast<std::size_t>(a)];
                std::mt19937_64 rng(1337 + a);
                std::uniform_real_distribution<double> dist01(0.0, 1.0);

                auto pick_file = [&cfg, &rng, &dist01](int d) -> std::string {
                    int f = static_cast<int>(rng() % static_cast<std::uint64_t>(cfg.files));
                    if (dist01(rng) < cfg.hot_fraction)
                        f = 0;
                    char buf[64];
                    std::snprintf(buf, sizeof(buf), "d%02d/pkg%02d/f%04d.txt", d, f % 16, f);
                    return buf;
                };

                for (int iter = 0; !stop.load(std::memory_order_relaxed); ++iter) {
                    auto f_res = repo.request(signedRequest({{"command", "fork"}}, agent.id, agent.seed));
                    if (!f_res)
                        continue;
                    auto ws = f_res->at("id").get<std::string>();

                    int d = static_cast<int>(rng() % static_cast<std::uint64_t>(cfg.domains));
                    std::vector<std::string> targets{pick_file(d)};
                    bool is_cross = false;
                    if (cfg.domains > 1 && dist01(rng) < cfg.cross_fraction) {
                        int d2 = static_cast<int>((d + 1 + (rng() % static_cast<std::uint64_t>(cfg.domains - 1))) %
                                                  cfg.domains);
                        targets.push_back(pick_file(d2));
                        is_cross = true;
                    }

                    // Perform extra reads
                    for (int r = 0; r < cfg.reads; ++r) {
                        auto rpath = pick_file(d);
                        (void)repo.request(
                            signedRequest({{"command", "cat"}, {"args", {ws, rpath}}}, agent.id, agent.seed));
                    }

                    // Modify target file(s)
                    for (auto const &tpath : targets) {
                        auto cat_res = repo.request(
                            signedRequest({{"command", "cat"}, {"args", {ws, tpath}}}, agent.id, agent.seed));
                        if (!cat_res || !cat_res->contains("bytes"))
                            continue;
                        auto body = axon::unhex(cat_res->at("bytes").get<std::string>());
                        std::istringstream stream(body);
                        std::string l1, l2, l3;
                        std::getline(stream, l1);
                        std::getline(stream, l2);
                        std::getline(stream, l3);

                        int line_to_edit = static_cast<int>(rng() % 3);
                        std::string new_line = "edit " + agent.id + " " + std::to_string(iter);
                        if (line_to_edit == 0)
                            l1 = new_line;
                        else if (line_to_edit == 1)
                            l2 = new_line;
                        else
                            l3 = new_line;
                        std::string new_content = l1 + "\n" + l2 + "\n" + l3 + "\n";

                        (void)repo.request(signedRequest(
                            {{"command", "write"}, {"args", {ws, tpath, "-"}}, {"input", axon::hex(new_content)}},
                            agent.id,
                            agent.seed));
                    }

                    // Submit and land
                    auto t0 = std::chrono::steady_clock::now();
                    auto land_res = repo.request(signedRequest(
                        {{"command", "stack"}, {"args", {ws}}, {"options", {{"title", "bench"}, {"land", "true"}}}},
                        agent.id,
                        agent.seed));
                    auto t1 = std::chrono::steady_clock::now();
                    auto lat_us = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();

                    if (land_res) {
                        auto st = land_res->value("status", "");
                        auto rt = land_res->value("route", "");
                        if (st == "landed") {
                            landings.fetch_add(1, std::memory_order_relaxed);
                            if (rt == "fast")
                                fast.fetch_add(1, std::memory_order_relaxed);
                            else if (rt == "rebase")
                                rebase.fetch_add(1, std::memory_order_relaxed);
                            else if (rt == "merge")
                                merge.fetch_add(1, std::memory_order_relaxed);
                            else
                                other.fetch_add(1, std::memory_order_relaxed);

                            if (is_cross)
                                cross_domain.fetch_add(1, std::memory_order_relaxed);

                            std::lock_guard lk(lats_mutex);
                            lats.push_back(lat_us);
                            char dbuf[16];
                            std::snprintf(dbuf, sizeof(dbuf), "d%02d", d);
                            domain_counts[dbuf]++;
                        } else if (st == "conflicted") {
                            conflicts.fetch_add(1, std::memory_order_relaxed);
                        } else {
                            other.fetch_add(1, std::memory_order_relaxed);
                        }
                    }

                    // Drop workspace
                    (void)repo.request(
                        signedRequest({{"command", "ws"}, {"args", {"drop", ws}}}, agent.id, agent.seed));
                }
            });
        }

        std::this_thread::sleep_for(std::chrono::seconds(cfg.duration_secs));
        stop.store(true);
        for (auto &t : threads) {
            if (t.joinable())
                t.join();
        }
        auto end = std::chrono::steady_clock::now();
        result.elapsed_secs = std::chrono::duration<double>(end - start).count();

        result.landings = landings.load();
        result.fast = fast.load();
        result.rebase = rebase.load();
        result.merge = merge.load();
        result.conflicts = conflicts.load();
        result.other = other.load();
        result.cross_domain = cross_domain.load();

        std::sort(lats.begin(), lats.end());
        if (!lats.empty()) {
            auto n = lats.size();
            result.p50_us = lats[n / 2];
            result.p90_us = lats[n * 9 / 10];
            result.p99_us = lats[n * 99 / 100];
            result.max_us = lats.back();
        }

        result.per_domain = domain_counts;
        int max_domain_landings = 0;
        for (auto const &[_, count] : domain_counts) {
            if (count > max_domain_landings)
                max_domain_landings = count;
        }
        result.busiest_domain_rate =
            result.elapsed_secs > 0 ? static_cast<double>(max_domain_landings) / result.elapsed_secs : 0.0;
    } catch (...) {
        if (cleanup_dir) {
            std::error_code ignored;
            std::filesystem::remove_all(work_dir, ignored);
        }
        throw;
    }

    if (cleanup_dir) {
        std::error_code ignored;
        std::filesystem::remove_all(work_dir, ignored);
    }

    return result;
}

} // namespace axon
