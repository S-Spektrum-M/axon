#include "bench.hpp"
#include "cache.hpp"
#include "fuse.hpp"
#include "git.hpp"
#include "graph.hpp"
#include "repository.hpp"
#include "spool.hpp"
#include "transport.hpp"

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <set>
#include <sstream>
#include <thread>

namespace axon {
namespace {
std::string env(std::string_view name, std::string_view fallback = "") {
    auto value = std::getenv(std::string(name).c_str());
    return value ? std::string(value) : std::string(fallback);
}
Path configDirectory() {
    auto override = env("AXON_HOME");
    if (!override.empty())
        return override;
    return Path(env("XDG_CONFIG_HOME", env("HOME", ".") + "/.config")) / "axon";
}
Json config() {
    auto path = configDirectory() / "config.json";
    auto value = std::filesystem::exists(path) ? Json::parse(axon::readFile(path)) : Json::object();
    value["server"] = env("AXON_SERVER", value.value("server", "http://127.0.0.1:7070"));
    value["principal"] = env("AXON_PRINCIPAL", value.value("principal", ""));
    value["key_file"] = env("AXON_KEY", value.value("key_file", ""));
    return value;
}
std::string seedAt(Path const &path, bool create) {
    if (!std::filesystem::exists(path)) {
        if (!create)
            throw std::runtime_error("no key file; run axon init or set AXON_KEY");
        axon::writeFile(path, axon::randomHex(32));
    }
    auto seed = axon::readFile(path);
    while (!seed.empty() && (seed.back() == '\n' || seed.back() == '\r'))
        seed.pop_back();
    (void)axon::publicKey(seed);
    return seed;
}
std::string shellQuote(std::string_view text) {
    std::string result = "'";
    for (char c : text) {
        if (c == '\'')
            result += "'\\''";
        else
            result += c;
    }
    return result + "'";
}
void usage() {
    std::cout << R"(axon — transactional source control in C++23
Usage: axon COMMAND [ARGS] [OPTIONS]

  init --data DIR [--admin human:NAME] [--server URL]
  serve --data DIR [--listen 127.0.0.1:7070] [--no-executors] [--auth-reads] [--build-query CMD] [--no-sync]
  # serve also accepts --tls-cert CERT.pem --tls-key KEY.pem
  cache [--upstream URL] [--listen 127.0.0.1:7071] [--dir DIR]
  keygen --principal ID [--out FILE]
  agent-key NAME [--ttl 24h]
  whoami
  fork [--from trunk@N | --ws ID] [-q]
  ws list|status|reads|drop|rebase [ID]
  symbol WS PATH QUALIFIED_NAME  # tracked C++ declaration read
  cat WS PATH                     ls WS [DIR]
  write WS PATH [FILE|-] [-x]      rm WS PATH       mv WS SRC DST
  # write, rm and mv accept --offline; use replay to send queued edits
  replay
  mount WS MOUNTPOINT              # foreground Linux FUSE filesystem
  get line@N PATH
  stack WS --title TITLE [--intent KIND] [--land] [--wait]
  status [STACK] [--all]           diff STACK
  land STACK                      review STACK [--reject]
  resolve STACK                   abandon STACK
  log [--line LINE] [--path PATH] [--limit N]  audit PATH       queue [--line LINE]
  lines                           line create NAME [--from trunk]
  targets [--at trunk@N]           affected PATH... [--at trunk@N]
  closure TARGET                  materialize TARGET DIR
  green [line@N] [--request]
  attest --target LABEL --input HASH --kind KIND --result passed|failed
  events [PARTITION] [--from OFFSET] [--follow] subscribe [--line LINE] [--paths GLOBS]
  admin add ID --key PUBLIC_HEX [--groups admins,...]
  admin policy [FILE]              admin workflows [FILE]           admin gc [--dry-run]
  admin compact                   admin prune [--age 30d] [--keep 100] [--dry-run]
  git import|export|push --repo DIR [--ref HEAD] [--line trunk]
  executor [--work DIR] [--once]   # requires a human/service identity
  metrics
  bench [--agents N] [--domains N] [--files N] [--duration S] [--sync]

All structured output is JSON; fork -q prints only the workspace ID.
Configuration: AXON_HOME/config.json (default ~/.config/axon), overridden by
AXON_SERVER, AXON_PRINCIPAL and AXON_KEY.
)";
}
} // namespace
} // namespace axon

int main(int argc, char **argv) {
    try {
        if (argc < 2 || std::string_view(argv[1]) == "help" || std::string_view(argv[1]) == "--help" ||
            std::string_view(argv[1]) == "-h") {
            axon::usage();
            return 0;
        }
        std::string command = argv[1];
        axon::Json options = axon::Json::object();
        std::vector<std::string> args;
        std::set<std::string> const FLAGS{"offline",
                                          "q",
                                          "x",
                                          "land",
                                          "wait",
                                          "all",
                                          "json",
                                          "reject",
                                          "request",
                                          "follow",
                                          "dry-run",
                                          "no-executors",
                                          "auth-reads",
                                          "no-sync",
                                          "incremental",
                                          "link",
                                          "once",
                                          "sync"};

        bool positional = false;
        for (int i = 2; i < argc; ++i) {
            std::string token = argv[i];
            if (!positional && (token == "--help" || token == "-h")) {
                axon::usage();
                return 0;
            }
            if (!positional && token == "--") {
                positional = true;
                continue;
            }
            if (!positional && token.starts_with('-') && token != "-") {
                auto offset = token.starts_with("--") ? 2 : 1;
                auto key = token.substr(offset);
                auto equal = key.find('=');
                if (equal != std::string::npos) {
                    options[key.substr(0, equal)] = key.substr(equal + 1);
                    continue;
                }
                if (FLAGS.contains(key))
                    options[key] = "true";
                else {
                    if (++i == argc)
                        throw std::runtime_error("missing value for " + token);
                    options[key] = argv[i];
                }
            } else
                args.push_back(token);
        }
        axon::Json const ALLOWED{
            {"init", {"data", "admin", "server", "out"}},
            {"serve",
             {"data", "listen", "no-executors", "auth-reads", "build-query", "no-sync", "tls-cert", "tls-key"}},
            {"cache", {"listen", "upstream", "dir"}},
            {"keygen", {"principal", "out"}},
            {"agent-key", {"ttl"}},
            {"whoami", axon::Json::array()},
            {"replay", axon::Json::array()},
            {"mount", axon::Json::array()},
            {"symbol", axon::Json::array()},
            {"fork", {"from", "ws", "session", "ttl", "q"}},
            {"ws", axon::Json::array()},
            {"cat", axon::Json::array()},
            {"ls", axon::Json::array()},
            {"get", axon::Json::array()},
            {"write", {"x", "link", "offline"}},
            {"rm", {"offline"}},
            {"mv", {"offline"}},
            {"stack",
             {"title",
              "intent",
              "note",
              "class",
              "labels",
              "assume-unrelated",
              "supersedes",
              "land",
              "wait",
              "timeout"}},
            {"status", {"all", "status", "json"}},
            {"queue", {"line"}},
            {"diff", {"json"}},
            {"land", {"wait", "timeout"}},
            {"review", {"reject", "m"}},
            {"resolve", {"q"}},
            {"abandon", axon::Json::array()},
            {"log", {"line", "path", "limit"}},
            {"audit", {"line"}},
            {"lines", axon::Json::array()},
            {"line", {"from"}},
            {"targets", {"at"}},
            {"closure", {"at"}},
            {"affected", {"at"}},
            {"materialize", {"at"}},
            {"green", {"at", "request"}},
            {"attest", {"target", "input", "kind", "result", "ttl"}},
            {"events", {"from", "follow", "partition", "group", "commit", "wait"}},
            {"subscribe", {"from", "line", "paths"}},
            {"admin", {"key", "groups", "dry-run", "age", "keep"}},
            {"metrics", axon::Json::array()},
            {"git", {"repo", "ref", "branch", "line", "land", "incremental"}},
            {"executor", {"work", "once"}},
            {"bench", {"agents", "domains", "files", "duration", "reads", "hot", "cross", "sync", "dir"}}};
        if (!ALLOWED.contains(command))
            throw std::runtime_error("unknown command: " + command);
        for (auto const &[name, value] : options.items()) {
            (void)value;
            if (std::find(ALLOWED.at(command).begin(), ALLOWED.at(command).end(), axon::Json(name)) ==
                ALLOWED.at(command).end())
                throw std::runtime_error("unsupported option for " + command + ": --" + name);
        }
        if (command == "cache") {
            axon::CacheConfig cfg;
            if (options.contains("listen"))
                cfg.listen = options["listen"].get<std::string>();
            if (options.contains("upstream"))
                cfg.upstream = options["upstream"].get<std::string>();
            if (options.contains("dir"))
                cfg.dir = options["dir"].get<std::string>();
            axon::serveCache(cfg);
            return 0;
        }
        if (command == "bench") {
            axon::BenchConfig cfg;
            if (options.contains("agents"))
                cfg.agents = std::stoi(options["agents"].get<std::string>());
            if (options.contains("domains"))
                cfg.domains = std::stoi(options["domains"].get<std::string>());
            if (options.contains("files"))
                cfg.files = std::stoi(options["files"].get<std::string>());
            if (options.contains("duration"))
                cfg.duration_secs = std::stoi(options["duration"].get<std::string>());
            if (options.contains("reads"))
                cfg.reads = std::stoi(options["reads"].get<std::string>());
            if (options.contains("hot"))
                cfg.hot_fraction = std::stod(options["hot"].get<std::string>());
            if (options.contains("cross"))
                cfg.cross_fraction = std::stod(options["cross"].get<std::string>());
            if (options.value("sync", "false") == "true")
                cfg.sync = true;
            if (options.contains("dir"))
                cfg.dir = options["dir"].get<std::string>();
            auto res = axon::runBench(cfg, std::cerr);
            res.print(std::cout);
            return 0;
        }
        if (command == "serve") {
            bool no_sync = options.value("no-sync", "false") == "true";
            axon::Repository repository(
                options.value("data", "axon-data"), options.value("no-executors", "false") != "true", no_sync);
            if (repository.inspect().empty())
                throw std::runtime_error("run axon init first");
            if (options.value("auth-reads", "false") == "true")
                repository.setAuthReads(true);
            if (options.contains("build-query"))
                repository.setBuildQuery(options["build-query"].get<std::string>());
            axon::serve(repository,
                        options.value("listen", "127.0.0.1:7070"),
                        options.value("tls-cert", ""),
                        options.value("tls-key", ""));
            return 0;
        }
        auto config = axon::config();
        if (command == "init" || command == "keygen") {
            auto principal =
                options.value(command == "init" ? "admin" : "principal", "human:" + axon::env("USER", "user"));
            auto key_path = axon::Path(options.value(
                "out", (axon::configDirectory() / "keys" / (axon::hash(principal).substr(0, 16) + ".key")).string()));
            auto seed = axon::seedAt(key_path, true);
            auto key = axon::publicKey(seed);
            if (command == "init") {
                axon::Repository repository(options.value("data", "axon-data"));
                repository.initialize(principal, key);
                config["principal"] = principal;
                config["key_file"] = std::filesystem::absolute(key_path).string();
                config["server"] = options.value("server", "http://127.0.0.1:7070");
                axon::writeFile(axon::configDirectory() / "config.json", config.dump(2));
            }
            std::cout
                << axon::Json{{"principal", principal}, {"public_key", key}, {"key_file", key_path.string()}}.dump(2)
                << '\n';
            return 0;
        }
        axon::Json request{{"command", command}, {"args", args}, {"options", options}};
        if (command == "get" || command == "cat")
            request["metadata_only"] = true;
        if (command == "write" ||
            (command == "admin" && args.size() > 1 && (args[0] == "policy" || args[0] == "workflows"))) {
            auto filename = command == "write" ? (args.size() > 2 ? args[2] : "-") : args[1];
            auto input =
                filename == "-" ? std::string(std::istreambuf_iterator<char>(std::cin), {}) : axon::readFile(filename);
            request["input"] = axon::hex(input);
        }
        auto principal = config.at("principal").get<std::string>();
        if (principal.empty())
            throw std::runtime_error("run axon init or configure AXON_PRINCIPAL and AXON_KEY");
        auto seed = axon::seedAt(config.at("key_file").get<std::string>(), false);
        if (command == "mount") {
            if (args.size() != 2)
                throw std::runtime_error("usage: axon mount WORKSPACE MOUNTPOINT");
            axon::mountWorkspace(args[0], args[1], config, seed);
            return 0;
        }
        if (options.value("offline", "false") == "true") {
            request["options"].erase("offline");
            std::cout << axon::spoolEdit(request, config).dump(2) << '\n';
            return 0;
        }
        if (command == "replay") {
            std::cout << axon::replayEdits(config, seed).dump(2) << '\n';
            return 0;
        }
        if (command == "subscribe") {
            while (true) {
                axon::streamRequest(config.at("server").get<std::string>(),
                                    axon::signedRequest(request, principal, seed),
                                    [&request](axon::Json const &event) {
                                        std::cout << event.dump() << std::endl;
                                        request["options"]["from"] =
                                            std::to_string(event.at("offset").get<std::size_t>() + 1);
                                    });
            }
        }
        if (command == "executor") {
            axon::Store cache(axon::configDirectory() / "cache");
            do {
                auto job = axon::remoteRequest(config.at("server").get<std::string>(),
                                               axon::signedRequest({{"command", "job-claim"}}, principal, seed));
                if (job.is_null()) {
                    if (options.value("once", "false") == "true")
                        return 0;
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                    continue;
                }
                auto work = axon::Path(options.value("work", std::filesystem::temp_directory_path().string())) /
                            ("axon-job-" + axon::randomHex());
                try {
                    for (auto const &[path, bytes] : job.at("contents").items()) {
                        auto id = cache.putBlob(axon::unhex(bytes.get<std::string>()));
                        if (job.at("files").at(path).at("hash") != id)
                            throw std::runtime_error("executor input hash mismatch");
                    }
                    axon::materialize(cache, job.at("files"), work);
                    std::vector<std::string> command_args{"env"};
                    for (auto const &[key, value] : job.at("definition").value("env", axon::Json::object()).items())
                        command_args.push_back(key + "=" + value.get<std::string>());
                    command_args.insert(command_args.end(),
                                        {"sh", "-c", job.at("definition").at("cmd").get<std::string>()});
                    auto result = axon::runProcess(command_args, work, "", 60);
                    auto claim = axon::remoteRequest(
                        config.at("server").get<std::string>(),
                        axon::signedRequest({{"command", "job-complete"},
                                             {"args", {job.at("id")}},
                                             {"options", {{"result", result.status == 0 ? "passed" : "failed"}}},
                                             {"input", axon::hex(result.output)},
                                             {"lease", job.at("lease")}},
                                            principal,
                                            seed));
                    std::cout << claim.dump() << std::endl;
                    std::filesystem::remove_all(work);
                } catch (...) {
                    std::error_code ignored;
                    std::filesystem::remove_all(work, ignored);
                    throw;
                }
            } while (options.value("once", "false") != "true");
            return 0;
        }
        if (command == "git") {
            std::cout << axon::gitBridge(args, options, config, seed).dump(2) << '\n';
            return 0;
        }
        if (command == "review") {
            if (args.empty())
                throw std::runtime_error("usage: review STACK");
            auto stack =
                axon::remoteRequest(config.at("server").get<std::string>(),
                                    axon::signedRequest({{"command", "status"}, {"args", args}}, principal, seed));
            request["review_subject"] = stack.at("review_subject");
        }
        std::string agent_seed;
        if (command == "agent-key") {
            agent_seed = axon::randomHex(32);
            request["public_key"] = axon::publicKey(agent_seed);
        }
        auto response =
            axon::remoteRequest(config.at("server").get<std::string>(), axon::signedRequest(request, principal, seed));
        if ((command == "stack" || command == "land") && options.value("wait", "false") == "true") {
            auto deadline =
                std::chrono::steady_clock::now() + std::chrono::seconds(std::stoi(options.value("timeout", "1800")));
            std::string previous;
            while (response.value("status", "") == "blocked" || response.value("status", "") == "submitted") {
                auto status = response.value("status", "") + ": " + response.value("reason", "");
                if (status != previous) {
                    std::cerr << status << '\n';
                    previous = status;
                }
                if (std::chrono::steady_clock::now() >= deadline)
                    throw std::runtime_error("waiting for landing timed out");
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
                response = axon::remoteRequest(
                    config.at("server").get<std::string>(),
                    axon::signedRequest({{"command", "status"}, {"args", {response.at("id")}}}, principal, seed));
            }
        }
        if (response.is_object() && response.contains("error"))
            throw std::runtime_error(response.at("error").get<std::string>());
        if (command == "agent-key") {
            auto identity = response.at("principal").get<std::string>();
            auto path = std::filesystem::absolute(axon::configDirectory() / "keys" /
                                                  (axon::hash(identity).substr(0, 16) + ".key"));
            axon::writeFile(path, agent_seed);
            std::cout << "export AXON_PRINCIPAL=" << axon::shellQuote(identity)
                      << "\nexport AXON_KEY=" << axon::shellQuote(path.string()) << '\n';
        } else if (response.is_object() && response.contains("blob"))
            std::cout << axon::cachedBlob(config.at("server").get<std::string>(),
                                          response.at("blob").get<std::string>());
        else if (response.is_object() && response.contains("bytes"))
            std::cout << axon::unhex(response.at("bytes").get<std::string>());
        else if ((command == "fork" || command == "resolve") && options.value("q", "false") == "true")
            std::cout << response.at("id").get<std::string>() << '\n';
        else if (command == "materialize") {
            if (args.size() < 2)
                throw std::runtime_error("usage: materialize TARGET DIR");
            auto target = axon::Path(args[1]);
            std::filesystem::create_directories(target);
            if (!std::filesystem::is_empty(target))
                throw std::runtime_error("destination must be empty");
            // Use a local CAS to apply the same path and symlink checks as executors.
            axon::Store cache(axon::configDirectory() / "cache");
            for (auto const &[path, bytes] : response.at("contents").items()) {
                auto id = cache.putBlob(axon::unhex(bytes.get<std::string>()));
                if (response.at("files").at(path).at("hash") != id)
                    throw std::runtime_error("materialized content hash mismatch");
            }
            axon::materialize(cache, response.at("files"), target);
            response.erase("contents");
            std::cout << response.dump(2) << '\n';
        } else if ((command == "events" && options.value("follow", "false") == "true") || command == "subscribe") {
            while (true) {
                for (auto const &event : response)
                    std::cout << event.dump() << std::endl;
                if (!response.empty())
                    request["options"]["from"] = std::to_string(response.back().at("offset").get<std::size_t>() + 1);
                std::this_thread::sleep_for(std::chrono::seconds(1));
                response = axon::remoteRequest(config.at("server").get<std::string>(),
                                               axon::signedRequest(request, principal, seed));
            }
        } else
            std::cout << response.dump(2) << '\n';
        if (command == "green" && !response.at("green").get<bool>())
            return 1;
        if ((command == "stack" || command == "land") && options.value("wait", "false") == "true" &&
            response.value("status", "") != "landed")
            return 1;
        return 0;
    } catch (std::exception const &error) {
        std::cerr << "axon: " << error.what() << '\n';
        return 1;
    }
}
