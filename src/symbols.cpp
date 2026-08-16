#include "symbols.hpp"

#include "graph.hpp"

#include <algorithm>
#include <mutex>
#include <stdexcept>

namespace axon {
std::optional<std::vector<Declaration>> declarations(std::string_view source) {
    // No preprocessing or filesystem access: a standalone declaration view must
    // not silently depend on headers outside the committed source tree.
    if (source.size() > 1024 * 1024 || source.find('#') != std::string_view::npos ||
        source.find('\0') != std::string_view::npos)
        return std::nullopt;
    static std::mutex mutex;
    static std::map<std::string, std::optional<std::vector<Declaration>>> cache;
    auto key = hash(source);
    {
        std::lock_guard lock(mutex);
        if (auto found = cache.find(key); found != cache.end())
            return found->second;
    }
    std::vector<std::string> args{"clang++-21",
                                  "-x",
                                  "c++",
                                  "-std=c++23",
                                  "-nostdinc",
                                  "-nostdinc++",
                                  "-fsyntax-only",
                                  "-w",
                                  "-Xclang",
                                  "-ast-dump=json",
                                  "-"};
    auto result = runProcess(args, std::filesystem::temp_directory_path(), source, 5);
    std::optional<std::vector<Declaration>> parsed;
    if (result.status == 0) {
        auto ast = Json::parse(result.output, nullptr, false);
        if (!ast.is_discarded()) {
            std::vector<Declaration> entries;
            auto visit = [&](auto const &self, Json const &node, std::string const &scope) -> void {
                for (auto const &item : node.value("inner", Json::array())) {
                    if (item.value("isImplicit", false) || !item.contains("loc") || !item.at("loc").contains("offset"))
                        continue;
                    auto name = item.value("name", "");
                    if (item.value("kind", "") == "NamespaceDecl") {
                        self(self, item, scope + name + "::");
                        continue;
                    }
                    auto range = item.value("range", Json::object());
                    if (name.empty() || !range.contains("begin") || !range.at("begin").contains("offset") ||
                        !range.contains("end") || !range.at("end").contains("offset"))
                        continue;
                    auto begin = range.at("begin").at("offset").get<std::size_t>();
                    auto end = range.at("end").at("offset").get<std::size_t>() +
                               range.at("end").value("tokLen", std::size_t{0});
                    if (end > source.size() || begin >= end)
                        continue;
                    auto identity = scope + name + ":" + item.value("kind", "") + ":" +
                                    item.value("type", Json::object()).value("qualType", "");
                    entries.push_back({scope + name, identity, begin, end});
                }
            };
            visit(visit, ast, "");
            std::ranges::sort(entries, {}, &Declaration::begin);
            bool valid = !entries.empty();
            std::set<std::string> identities;
            std::size_t end = 0;
            for (auto const &entry : entries) {
                valid &= entry.begin >= end && identities.insert(entry.identity).second;
                end = entry.end;
            }
            if (valid)
                parsed = std::move(entries);
        }
    }
    {
        std::lock_guard lock(mutex);
        if (cache.size() >= 256)
            cache.erase(cache.begin());
        cache[key] = parsed;
    }
    return parsed;
}
Json readSymbol(std::string_view source, std::string_view name) {
    auto parsed = declarations(source);
    if (!parsed)
        throw std::runtime_error("symbol reads require self-contained C++23 without preprocessor directives");
    std::string bytes;
    Json identities = Json::array();
    for (auto const &entry : *parsed)
        if (entry.name == name || entry.identity == name) {
            if (!bytes.empty())
                bytes += '\n';
            bytes += source.substr(entry.begin, entry.end - entry.begin);
            identities.push_back(entry.identity);
        }
    return {{"bytes", hex(bytes)}, {"identities", identities}, {"hash", hash(Json::array({identities, bytes}).dump())}};
}
std::optional<std::string> mergeDeclarations(std::string_view base, std::string_view ours, std::string_view theirs) {
    auto a = declarations(base), b = declarations(ours), c = declarations(theirs);
    if (!a || !b || !c || a->size() != b->size() || a->size() != c->size())
        return std::nullopt;
    std::string result;
    std::size_t pa = 0, pb = 0, pc = 0;
    for (std::size_t i = 0; i < a->size(); ++i) {
        auto const &x = a->at(i), &y = b->at(i), &z = c->at(i);
        if (x.identity != y.identity || x.identity != z.identity)
            return std::nullopt;
        auto gap = base.substr(pa, x.begin - pa);
        if (gap != ours.substr(pb, y.begin - pb) || gap != theirs.substr(pc, z.begin - pc))
            return std::nullopt;
        auto original = base.substr(x.begin, x.end - x.begin);
        auto left = ours.substr(y.begin, y.end - y.begin);
        auto right = theirs.substr(z.begin, z.end - z.begin);
        if (left != original && right != original && left != right)
            return std::nullopt;
        result += gap;
        result += left == original ? right : left;
        pa = x.end;
        pb = y.end;
        pc = z.end;
    }
    if (base.substr(pa) != ours.substr(pb) || base.substr(pa) != theirs.substr(pc))
        return std::nullopt;
    result += base.substr(pa);
    if (!declarations(result))
        return std::nullopt;
    return result;
}
} // namespace axon
