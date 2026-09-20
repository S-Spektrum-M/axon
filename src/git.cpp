#include "git.hpp"

#include "graph.hpp"
#include "repository.hpp"
#include "transport.hpp"

#include <sstream>
#include <stdexcept>

namespace axon {
namespace {
std::string git(Path const &repo, std::vector<std::string> const &args, std::string_view input = "") {
    std::vector<std::string> command{"git", "-C", repo.string()};
    command.insert(command.end(), args.begin(), args.end());
    auto result = axon::runProcess(command, ".", input);
    if (result.status != 0)
        throw std::runtime_error("git: " + result.output);
    return result.output;
}
Json gitFiles(Path const &repo, std::string_view revision) {
    auto listing = git(repo, {"ls-tree", "-r", "-z", std::string(revision)});
    Json files = Json::object();
    std::size_t start = 0;
    while (start < listing.size()) {
        auto end = listing.find('\0', start);
        if (end == std::string::npos)
            throw std::runtime_error("invalid git ls-tree output");
        auto record = listing.substr(start, end - start);
        auto tab = record.find('\t');
        if (tab == std::string::npos)
            throw std::runtime_error("invalid git entry");
        std::istringstream metadata(record.substr(0, tab));
        std::string mode, kind, oid;
        metadata >> mode >> kind >> oid;
        if (kind != "blob")
            throw std::runtime_error("Git submodules are not representable as Axon files");
        auto name = axon::cleanPath(record.substr(tab + 1));
        auto bytes = git(repo, {"cat-file", "blob", oid});
        files[name] = {
            {"kind", mode == "120000" ? "link" : "file"}, {"exec", mode == "100755"}, {"bytes", axon::hex(bytes)}};
        start = end + 1;
    }
    return files;
}
} // namespace
Json gitBridge(std::span<std::string const> args, Json const &options, Json const &config, std::string_view seed) {
    if (args.empty())
        throw std::runtime_error("usage: git import|export|push --repo DIR");
    auto repo = Path(options.value("repo", "."));
    auto line = options.value("line", "trunk");
    auto request =
        [&config,
         seed](std::string_view command, Json const &arguments, Json const &opts, Json const &extra = Json::object()) {
            Json payload{{"command", command}, {"args", arguments}, {"options", opts}};
            payload.update(extra);
            return axon::remoteRequest(config.at("server").get<std::string>(),
                                       axon::signedRequest(payload, config.at("principal").get<std::string>(), seed));
        };
    if (args[0] == "export") {
        auto branch = options.value("branch", "axon/" + line);
        auto ref = "refs/heads/" + branch;
        (void)git(repo, {"check-ref-format", ref});
        std::vector<std::string> exists{"git", "-C", repo.string(), "show-ref", "--verify", "--quiet", ref};
        bool branch_exists = axon::runProcess(exists, ".").status == 0;
        if (branch_exists && options.value("incremental", "false") != "true")
            throw std::runtime_error("export branch already exists; choose a new --branch");
        auto history = request("log", Json::array(), {{"line", line}});
        std::string stream;
        std::size_t mark = 0;
        for (auto const &landing : history) {
            if (!landing.contains("stack"))
                continue;
            auto snapshot = request("snapshot-files",
                                    Json::array({line + "@" + std::to_string(landing.at("n").get<std::size_t>())}),
                                    Json::object());
            auto principal_str = landing.at("principal").get<std::string>();
            std::string author_name = principal_str;
            std::string author_email = "axon@localhost";
            auto colon = principal_str.find(':');
            if (colon != std::string::npos) {
                author_name = principal_str.substr(colon + 1);
                auto at = author_name.find('@');
                if (at != std::string::npos)
                    author_email = author_name.substr(0, at) + "@" + author_name.substr(at + 1) + ".local";
                else
                    author_email = author_name + "@axon.local";
            }
            auto created_time = std::to_string(landing.at("created").get<std::int64_t>());
            auto message = landing.value("title", "Axon landing") +
                           "\n\nAxon-Stack: " + landing.at("stack").get<std::string>() +
                           "\nAxon-Principal: " + principal_str + "\n";
            ++mark;
            auto author =
                landing.value("git_author", author_name + " <" + author_email + "> " + created_time + " +0000");
            if (author.find_first_of("\r\n") != std::string::npos || author.find('\0') != std::string::npos)
                throw std::runtime_error("invalid Git author metadata");
            stream += "commit " + ref + "\nmark :" + std::to_string(mark) + "\nauthor " + author +
                      "\ncommitter Axon <axon@localhost> " + created_time + " +0000\ndata " +
                      std::to_string(message.size()) + "\n" + message + "\n";
            if (mark > 1)
                stream += "from :" + std::to_string(mark - 1) + "\n";
            else if (branch_exists)
                stream += "from " + ref + "^0\n";
            stream += "deleteall\n";
            for (auto const &[path, entry] : snapshot.items()) {
                auto bytes = axon::unhex(entry.at("bytes").get<std::string>());
                auto mode = entry.at("kind") == "link" ? "120000" : (entry.value("exec", false) ? "100755" : "100644");
                stream += std::string("M ") + mode + " inline " + Json(path).dump() + "\ndata " +
                          std::to_string(bytes.size()) + "\n" + bytes + "\n";
            }
            stream += "\n";
        }
        stream += "done\n";
        (void)git(repo, {"fast-import", "--quiet"}, stream);
        return Json{{"exported", mark}, {"branch", branch}};
    }
    if (args[0] != "import" && args[0] != "push")
        throw std::runtime_error("unknown git subcommand");
    auto ref = options.value("ref", "HEAD");
    // Resolve untrusted ref text after --end-of-options before any other command.
    auto oid = git(repo, {"rev-parse", "--verify", "--end-of-options", ref + "^{commit}"});
    while (!oid.empty() && oid.back() == '\n')
        oid.pop_back();
    auto revisions = args[0] == "push" ? oid + "\n" : git(repo, {"rev-list", "--reverse", "--first-parent", oid});
    std::istringstream commits(revisions);
    std::string commit;
    Json result = Json::array();
    while (std::getline(commits, commit)) {
        auto title = git(repo, {"show", "-s", "--format=%s", commit});
        while (!title.empty() && title.back() == '\n')
            title.pop_back();
        std::istringstream metadata(git(repo, {"cat-file", "commit", commit}));
        std::string header, author;
        while (std::getline(metadata, header) && !header.empty())
            if (header.starts_with("author "))
                author = header.substr(7);
        auto staged = request("git-stage",
                              Json::array(),
                              {{"line", line}, {"title", title}, {"imported", args[0] == "import" ? "true" : "false"}},
                              {{"files", gitFiles(repo, commit)}, {"git_commit", commit}, {"git_author", author}});
        if (staged.contains("skipped")) {
            result.push_back(staged);
            continue;
        }
        auto stack =
            request("stack",
                    Json::array({staged.at("id")}),
                    {{"title", title.empty() ? "Git change" : title}, {"land", options.value("land", "true")}});
        result.push_back(stack);
        if (stack.value("status", "") != "landed")
            break;
    }
    return result;
}
} // namespace axon
