#include "graph.hpp"

#include "symbols.hpp"

#include <algorithm>
#include <chrono>
#include <fcntl.h>
#include <fstream>
#include <list>
#include <regex>
#include <signal.h>
#include <stdexcept>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
#include <unordered_map>

namespace axon {
namespace {
class TemporaryDirectory {
public:
    TemporaryDirectory() : path_(std::filesystem::temp_directory_path() / ("axon-" + axon::randomHex())) {
        std::filesystem::create_directory(path_);
        std::filesystem::permissions(path_, std::filesystem::perms::owner_all);
    }
    ~TemporaryDirectory() {
        std::error_code ignored;
        std::filesystem::remove_all(path_, ignored);
    }
    TemporaryDirectory(TemporaryDirectory const &) = delete;
    TemporaryDirectory &operator=(TemporaryDirectory const &) = delete;
    [[nodiscard]] Path path() const {
        return path_;
    }

private:
    Path path_;
};
std::string label(std::string_view package, std::string_view name) {
    if (name.starts_with("//"))
        return std::string(name);
    if (name.starts_with(':'))
        name.remove_prefix(1);
    return "//" + std::string(package) + ":" + std::string(name);
}
} // namespace
ProcessResult runProcess(std::span<std::string const> args,
                         Path const &directory,
                         std::string_view input,
                         int timeout_seconds,
                         std::stop_token stop) {
    if (args.empty())
        throw std::runtime_error("empty process command");
    TemporaryDirectory temp;
    auto input_path = temp.path() / "input";
    auto output_path = temp.path() / "output";
    axon::writeFile(input_path, input);
    Descriptor input_fd(::open(input_path.c_str(), O_RDONLY | O_CLOEXEC));
    Descriptor output_fd(::open(output_path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600));
    std::vector<char *> argv;
    for (auto const &arg : args)
        argv.push_back(const_cast<char *>(arg.c_str()));
    argv.push_back(nullptr);
    auto child = ::fork();
    if (child < 0)
        throw std::runtime_error("fork failed");
    if (child == 0) {
        ::setpgid(0, 0);
        if (::chdir(directory.c_str()) != 0 || ::dup2(input_fd.get(), STDIN_FILENO) < 0 ||
            ::dup2(output_fd.get(), STDOUT_FILENO) < 0 || ::dup2(output_fd.get(), STDERR_FILENO) < 0)
            ::_exit(126);
        ::execvp(argv[0], argv.data());
        ::_exit(127);
    }
    ::setpgid(child, child);
    int status = 0;
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout_seconds);
    bool timed_out = false;
    while (true) {
        auto result = ::waitpid(child, &status, WNOHANG);
        if (result == child)
            break;
        if (result < 0 && errno != EINTR)
            throw std::runtime_error("waitpid failed");
        if (stop.stop_requested() || std::chrono::steady_clock::now() >= deadline) {
            timed_out = true;
            ::kill(-child, SIGKILL);
            while (::waitpid(child, &status, 0) < 0 && errno == EINTR) {
            }
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    // Kill surviving descendants before deleting their working directory.
    ::kill(-child, SIGKILL);
    return {timed_out ? 124 : (WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status)),
            axon::readFile(output_path)};
}
bool matches(std::string_view pattern, std::string_view path) {
    std::string expression = "^";
    for (std::size_t i = 0; i < pattern.size(); ++i) {
        char c = pattern[i];
        if (c == '*') {
            if (i + 1 < pattern.size() && pattern[i + 1] == '*') {
                ++i;
                if (i + 1 < pattern.size() && pattern[i + 1] == '/') {
                    ++i;
                    expression += "(.*/)?";
                } else
                    expression += ".*";
            } else
                expression += "[^/]*";
        } else if (c == '?')
            expression += "[^/]";
        else {
            if (std::string_view(".[]{}()+^$|\\").find(c) != std::string_view::npos)
                expression += '\\';
            expression += c;
        }
    }
    expression += '$';
    return std::regex_match(path.begin(), path.end(), std::regex(expression));
}
void materialize(Store const &store, Json const &files, Path const &directory) {
    std::filesystem::create_directories(directory);
    // Never follow pre-existing symlinks or overwrite a populated destination.
    if (!std::filesystem::is_empty(directory))
        throw std::runtime_error("materialize destination must be empty");
    for (auto const &[name, entry] : files.items()) {
        auto path = directory / axon::cleanPath(name);
        if (entry.at("kind") == "link")
            continue;
        axon::writeFile(
            path, store.blob(entry.at("hash").get<std::string>()), entry.value("exec", false) ? 0755 : 0644);
    }
    for (auto const &[name, entry] : files.items()) {
        if (entry.at("kind") != "link")
            continue;
        auto path = directory / axon::cleanPath(name);
        auto target = store.blob(entry.at("hash").get<std::string>());
        // A closure is executable input: external symlink targets are not in it.
        if (Path(target).is_absolute())
            throw std::runtime_error("absolute symlink in closure");
        (void)axon::cleanPath((Path(name).parent_path() / target).generic_string());
        std::filesystem::create_directories(path.parent_path());
        std::filesystem::create_symlink(target, path);
    }
}
Json mergeFile(Store &store, Json const &base, Json const &ours, Json const &theirs) {
    if (ours == base || ours == theirs)
        return Json{{"entry", theirs}, {"conflict", false}};
    if (theirs == base)
        return Json{{"entry", ours}, {"conflict", false}};
    if (base.is_null() || ours.is_null() || theirs.is_null() || base.value("kind", "") != "file" ||
        ours.value("kind", "") != "file" || theirs.value("kind", "") != "file")
        return Json{{"entry", ours}, {"conflict", true}};
    auto a = store.blob(base.at("hash").get<std::string>());
    auto b = store.blob(ours.at("hash").get<std::string>());
    auto c = store.blob(theirs.at("hash").get<std::string>());
    if (a.find('\0') != std::string::npos || b.find('\0') != std::string::npos || c.find('\0') != std::string::npos)
        return Json{{"entry", ours}, {"conflict", true}};
    if (auto declaration_merge = mergeDeclarations(a, b, c)) {
        auto result = ours;
        result["hash"] = store.putBlob(*declaration_merge);
        result["size"] = declaration_merge->size();
        if (ours.value("exec", false) == base.value("exec", false))
            result["exec"] = theirs.value("exec", false);
        return {{"entry", result}, {"conflict", false}};
    }
    TemporaryDirectory temp;
    axon::writeFile(temp.path() / "base", a);
    axon::writeFile(temp.path() / "ours", b);
    axon::writeFile(temp.path() / "theirs", c);
    std::vector<std::string> command{
        "git", "merge-file", "-p", "--diff3", "-L", "stack", "-L", "base", "-L", "head", "ours", "base", "theirs"};
    auto merged = axon::runProcess(command, temp.path());
    if (merged.status > 127)
        throw std::runtime_error("merge-file failed: " + merged.output);
    auto result = ours;
    result["hash"] = store.putBlob(merged.output);
    result["size"] = merged.output.size();
    // If only trunk changed the executable bit, retain it.
    if (ours.value("exec", false) == base.value("exec", false))
        result["exec"] = theirs.value("exec", false);
    return Json{{"entry", result}, {"conflict", merged.status != 0}};
}
std::string unifiedDiff(Store const &store, Json const &changes) {
    TemporaryDirectory temp;
    std::string output;
    for (auto const &change : changes) {
        auto path = change.at("path").get<std::string>();
        auto old = change.at("old");
        auto next = change.at("new");
        auto before = old.is_null() ? "" : store.blob(old.at("hash").get<std::string>());
        auto after = next.is_null() ? "" : store.blob(next.at("hash").get<std::string>());
        axon::writeFile(temp.path() / "before", before);
        axon::writeFile(temp.path() / "after", after);
        output += "diff --axon a/" + path + " b/" + path + "\n";
        if (!old.is_null() && !next.is_null() &&
            (old.value("exec", false) != next.value("exec", false) || old.at("kind") != next.at("kind")))
            output += "mode " + old.at("kind").get<std::string>() + (old.value("exec", false) ? "+x" : "") + " -> " +
                      next.at("kind").get<std::string>() + (next.value("exec", false) ? "+x" : "") + "\n";
        std::vector<std::string> command{"diff",
                                         "-u",
                                         "--label",
                                         old.is_null() ? "/dev/null" : "a/" + path,
                                         "--label",
                                         next.is_null() ? "/dev/null" : "b/" + path,
                                         "before",
                                         "after"};
        auto result = axon::runProcess(command, temp.path());
        if (result.status > 1)
            throw std::runtime_error("diff failed: " + result.output);
        output += result.output;
    }
    return output;
}
namespace {
static std::mutex g_cache_mutex;
struct CachedGraph {
    std::shared_ptr<Graph> graph;
    std::size_t weight;
    std::list<std::string>::iterator position;
};
std::unordered_map<std::string, CachedGraph> g_graph_cache;
std::list<std::string> g_graph_recency;
std::size_t g_graph_weight = 0;
constexpr std::size_t MAX_GRAPHS = 64;
constexpr std::size_t MAX_GRAPH_WEIGHT = 64 * 1024 * 1024;
} // namespace

Graph::Graph(Store const &store, std::string_view root, std::string_view query_engine)
    : store_(store), root_(root), files_(store.files(root)) {
    for (auto const &[path, entry] : files_.items()) {
        if (Path(path).filename() != "BUILD.axon" || entry.at("kind") != "file")
            continue;
        auto package = Path(path).parent_path().generic_string();
        auto raw_content = store_.blob(entry.at("hash").get<std::string>());
        Json build;
        if (!query_engine.empty()) {
            std::vector<std::string> env_cmd{"env", "AXON_PKG=" + package, "sh", "-c", std::string(query_engine)};
            auto res = axon::runProcess(env_cmd, ".", raw_content);
            if (res.status != 0)
                throw std::runtime_error("build query engine failed for " + package + ": " + res.output);
            build = Json::parse(res.output);
        } else {
            build = Json::parse(raw_content);
        }
        for (auto definition : build.at("targets")) {
            auto name = definition.at("name").get<std::string>();
            if (name.empty() || name.find_first_of("/:") != std::string::npos)
                throw std::runtime_error("invalid target name");
            auto target = label(package, name);
            if (targets_.contains(target))
                throw std::runtime_error("duplicate target " + target);
            Json dependencies = Json::array();
            for (auto const &dep : definition.value("deps", Json::array()))
                dependencies.push_back(label(package, dep.get<std::string>()));
            targets_[target] = {
                {"label", target}, {"pkg", package}, {"def", definition}, {"deps", dependencies}, {"build", path}};
        }
    }
}

std::shared_ptr<Graph> GraphCache::get(Store const &store, std::string_view root, std::string_view query_engine) {
    auto key =
        Json::array({std::filesystem::absolute(store.directory()).lexically_normal().string(), root, query_engine})
            .dump();
    {
        std::lock_guard lock(g_cache_mutex);
        auto it = g_graph_cache.find(key);
        if (it != g_graph_cache.end()) {
            g_graph_recency.splice(g_graph_recency.begin(), g_graph_recency, it->second.position);
            return it->second.graph;
        }
    }
    // Graph construction can invoke a query process; never hold the cache lock here.
    auto graph = std::make_shared<Graph>(store, root, query_engine);
    auto weight = graph->cacheWeight();
    if (weight > MAX_GRAPH_WEIGHT)
        return graph;
    std::lock_guard lock(g_cache_mutex);
    if (auto it = g_graph_cache.find(key); it != g_graph_cache.end())
        return it->second.graph;
    while (!g_graph_cache.empty() &&
           (g_graph_cache.size() >= MAX_GRAPHS || g_graph_weight + weight > MAX_GRAPH_WEIGHT)) {
        auto oldest = g_graph_cache.find(g_graph_recency.back());
        g_graph_weight -= oldest->second.weight;
        g_graph_cache.erase(oldest);
        g_graph_recency.pop_back();
    }
    g_graph_recency.push_front(key);
    g_graph_cache.emplace(key, CachedGraph{graph, weight, g_graph_recency.begin()});
    g_graph_weight += weight;
    return graph;
}

void GraphCache::clear() {
    std::lock_guard lock(g_cache_mutex);
    g_graph_cache.clear();
    g_graph_recency.clear();
    g_graph_weight = 0;
}

std::size_t Graph::cacheWeight() const {
    return files_.dump().size() + targets_.dump().size() + root_.size();
}

Json const &Graph::targets() const {
    return targets_;
}
void Graph::collect(std::string_view name, std::set<std::string> &visiting, Json &files, Json &definitions) const {
    auto target_name = std::string(name);
    if (!targets_.contains(target_name))
        throw std::runtime_error("unknown target " + target_name);
    if (visiting.contains(target_name))
        throw std::runtime_error("dependency cycle at " + target_name);
    if (definitions.contains(target_name))
        return;
    visiting.insert(target_name);
    auto target = targets_.at(target_name);
    auto package = target.at("pkg").get<std::string>();
    auto prefix = package.empty() ? "" : package + "/";
    auto build = target.at("build").get<std::string>();
    files[build] = files_.at(build);
    for (auto const &[path, entry] : files_.items()) {
        if (!path.starts_with(prefix))
            continue;
        for (auto const &pattern : target.at("def").value("srcs", Json::array())) {
            if (axon::matches(pattern.get<std::string>(), path.substr(prefix.size())))
                files[path] = entry;
        }
    }
    for (auto const &dependency : target.at("deps"))
        collect(dependency.get<std::string>(), visiting, files, definitions);
    visiting.erase(target_name);
    definitions[target_name] = target;
}
Json Graph::closure(std::string_view target) const {
    Json files = Json::object();
    Json definitions = Json::object();
    std::set<std::string> visiting;
    collect(target, visiting, files, definitions);
    auto digest = axon::hash(Json{{"files", files}, {"definitions", definitions}}.dump());
    return Json{{"target", target}, {"input_hash", digest}, {"files", files}, {"definitions", definitions}};
}
Json Graph::affected(Json const &paths) const {
    Json result = Json::array();
    for (auto const &[name, target] : targets_.items()) {
        auto input = closure(name);
        bool hit = false;
        for (auto const &path : paths) {
            auto p = path.get<std::string>();
            if (input.at("files").contains(p))
                hit = true;
            // Match missing/deleted and newly created glob inputs as well.
            for (auto const &[dependency, definition] : input.at("definitions").items()) {
                (void)dependency;
                auto package = definition.at("pkg").get<std::string>();
                auto prefix = package.empty() ? "" : package + "/";
                if (!p.starts_with(prefix))
                    continue;
                for (auto const &pattern : definition.at("def").value("srcs", Json::array()))
                    if (axon::matches(pattern.get<std::string>(), p.substr(prefix.size())))
                        hit = true;
            }
        }
        if (hit)
            result.push_back(name);
        (void)target;
    }
    return result;
}
} // namespace axon
