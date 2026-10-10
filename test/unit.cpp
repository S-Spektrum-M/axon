#include "filesystem.hpp"
#include "fuse.hpp"
#include "graph.hpp"
#include "policy.hpp"
#include "repository.hpp"
#include "retention.hpp"
#include "storage.hpp"
#include "symbols.hpp"

#include <csignal>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <linux/fuse.h>
#include <stdexcept>
#include <sys/resource.h>
#include <thread>
#include <vector>

namespace axon::test {
namespace {
void check(bool condition, std::string_view message) {
    if (!condition)
        throw std::runtime_error(std::string(message));
}
class Directory {
public:
    Directory() : path(std::filesystem::temp_directory_path() / ("axon-unit-" + axon::randomHex())) {
        std::filesystem::create_directory(path);
    }
    ~Directory() {
        std::error_code ignored;
        std::filesystem::remove_all(path, ignored);
    }
    Directory(Directory const &) = delete;
    Directory &operator=(Directory const &) = delete;
    Path path;
};
void symbolReadsAndMerges() {
    std::string base = "namespace n { int a(){return 1;} int b(){return 2;} }\n";
    std::string ours = "namespace n { int a(){return 3;} int b(){return 2;} }\n";
    std::string theirs = "namespace n { int a(){return 1;} int b(){return 4;} }\n";
    auto original = readSymbol(base, "n::a");
    check(original.at("hash") == readSymbol(theirs, "n::a").at("hash"), "unrelated declaration does not stale symbol");
    check(original.at("hash") != readSymbol(ours, "n::a").at("hash"), "changed declaration stales symbol");
    auto merged = mergeDeclarations(base, ours, theirs);
    check(merged && *merged == "namespace n { int a(){return 3;} int b(){return 4;} }\n",
          "adjacent C++ declarations merge independently");
    check(!mergeDeclarations(base, ours, "namespace n { int a(){return 7;} int b(){return 2;} }\n"),
          "same declaration conflict falls back");
    check(!declarations("#include <string>\nstd::string value;"), "preprocessor dependency is not silently ignored");
}
void filesystemProtocol() {
    Directory directory;
    Store store(directory.path);
    Json workspace{{"root", store.empty()}, {"reads", Json::array()}, {"drafts", Json::array()}};
    FuseSession session([&](Json request) { return filesystemRequest(store, workspace, request); });
    auto packet = [&](std::uint32_t opcode, std::uint64_t node, std::string body) {
        fuse_in_header header{};
        header.len = static_cast<std::uint32_t>(sizeof(header) + body.size());
        header.opcode = opcode;
        header.nodeid = node;
        header.unique = 1;
        std::string bytes(reinterpret_cast<char const *>(&header), sizeof(header));
        auto response = session.dispatch(bytes + body);
        check(response.size() >= sizeof(fuse_out_header), "FUSE reply header");
        fuse_out_header reply{};
        std::memcpy(&reply, response.data(), sizeof(reply));
        check(reply.unique == 1 && reply.len == response.size() && reply.error == 0, "FUSE operation succeeded");
        return response.substr(sizeof(reply));
    };
    auto bytes = [](auto const &value) { return std::string(reinterpret_cast<char const *>(&value), sizeof(value)); };
    fuse_init_in init{};
    init.major = 7;
    init.minor = 31;
    check(packet(FUSE_INIT, 0, bytes(init)).size() == 64, "FUSE negotiated response size");
    fuse_create_in create{};
    create.mode = 0600;
    auto created = packet(FUSE_CREATE, 1, bytes(create) + std::string("file\0", 5));
    fuse_entry_out entry{};
    std::memcpy(&entry, created.data(), sizeof(entry));
    fuse_write_in write{};
    write.size = 5;
    (void)packet(FUSE_WRITE, entry.nodeid, bytes(write) + "hello");
    fuse_read_in read{};
    read.size = 20;
    check(packet(FUSE_READ, entry.nodeid, bytes(read)) == "hello", "FUSE write/read roundtrip");
    fuse_rename_in rename{};
    rename.newdir = 1;
    (void)packet(FUSE_RENAME, 1, bytes(rename) + std::string("file\0renamed\0", 13));
    check(packet(FUSE_READ, entry.nodeid, bytes(read)) == "hello", "open inode follows rename");
    fuse_setattr_in truncate{};
    truncate.valid = FATTR_SIZE;
    truncate.size = 2;
    (void)packet(FUSE_SETATTR, entry.nodeid, bytes(truncate));
    check(packet(FUSE_READ, entry.nodeid, bytes(read)) == "he", "FUSE truncate");
    fuse_setattr_in touch{};
    touch.valid = FATTR_MTIME;
    touch.mtime = 123;
    auto touched = packet(FUSE_SETATTR, entry.nodeid, bytes(touch));
    fuse_attr_out touched_attr{};
    std::memcpy(&touched_attr, touched.data(), sizeof(touched_attr));
    check(touched_attr.attr.mtime == 123, "FUSE mount-session timestamp update");
    auto attributes = packet(FUSE_GETATTR, entry.nodeid, "");
    std::memcpy(&touched_attr, attributes.data(), sizeof(touched_attr));
    check(touched_attr.attr.mtime == 123, "unchanged content retains its timestamp");
    check(!workspace.at("reads").empty(), "filesystem reads enter workspace read set");
    auto mkdir = filesystemRequest(store, workspace, {{"action", "mkdir"}, {"path", "dir"}});
    check(mkdir.at("kind") == "dir", "create explicit directory");
    (void)filesystemRequest(store, workspace, {{"action", "create"}, {"path", "dir/child"}});
    (void)filesystemRequest(store, workspace, {{"action", "unlink"}, {"path", "dir/child"}});
    check(filesystemRequest(store, workspace, {{"action", "stat"}, {"path", "dir"}}).at("kind") == "dir",
          "explicit empty directory survives child removal");
}
void retention() {
    Directory directory;
    Database database(directory.path);
    auto timestamp = now() - 100;
    database.commit({{"workspaces", {{"live", {{"touched", now()}, {"ttl", 1000}, {"base", {{"root", "pinned"}}}}}}},
                     {"stacks", Json::object()},
                     {"jobs", Json::object()},
                     {"attestations", Json::array()},
                     {"events", Json::array()},
                     {"partitions", Json::object()},
                     {"lines",
                      {{"trunk",
                        Json::array({{{"n", 0}, {"root", "prunable"}, {"created", timestamp}},
                                     {{"n", 1}, {"root", "pinned"}, {"created", timestamp}},
                                     {{"n", 2}, {"root", "head"}, {"created", timestamp}}})}}}});
    auto tx = database.transaction();
    auto preview = pruneMetadata(tx, now() - 1, 1, true);
    check(preview.at("snapshots") == 1, "retention preview respects pins");
    check(tx.at("lines")["trunk"][0].contains("root"), "retention dry run leaves state intact");
    (void)pruneMetadata(tx, now() - 1, 1, false);
    check(database.commit(tx), "retention transaction commits");
    auto line = database.state()["lines"]["trunk"];
    check(line[0].at("pruned") == true && line[1].at("root") == "pinned" && line[2].at("n") == 2,
          "retention keeps stable history positions and active bases");
}
void replayIds() {
    Directory directory;
    auto seed = randomHex(32);
    Repository repository(directory.path, false);
    repository.initialize("human:test", publicKey(seed));
    auto request = [&](Json payload) {
        auto result = repository.request(signedRequest(payload, "human:test", seed));
        check(result.has_value(), result ? "" : result.error());
        return *result;
    };
    auto ws = request({{"command", "fork"}}).at("id");
    Json edit{{"command", "write"}, {"args", {ws, "file"}}, {"input", hex("hello")}, {"operation_id", randomHex()}};
    auto first = request(edit);
    check(request(edit) == first, "replay returns original result with fresh envelope");
    check(repository.inspect()["workspaces"][ws.get<std::string>()]["drafts"].size() == 1,
          "replay does not duplicate workspace edits");
    edit["input"] = hex("changed");
    check(!repository.request(signedRequest(edit, "human:test", seed)),
          "operation ID cannot be reused with different content");
}
void transactions() {
    Directory directory;
    {
        Database database(directory.path);
        database.commit({{"workspaces", {{"a", {{"root", "old"}}}, {"b", {{"root", "old"}}}}},
                         {"events", Json::array()},
                         {"partitions", Json::object()}});
        auto first = database.transaction();
        auto second = database.transaction();
        first.edit("workspaces", "a")["root"] = "first";
        second.edit("workspaces", "b")["root"] = "second";
        first.emit({{"partition", "events"}, {"kind", "first"}});
        second.emit({{"partition", "events"}, {"kind", "second"}});
        check(database.commit(first), "first transaction commits");
        check(database.commit(second), "disjoint prepared transaction commits without retry");
        auto stale = database.transaction();
        check(stale.record("workspaces", "a").at("root") == "first", "snapshot read");
        auto update = database.transaction();
        update.edit("workspaces", "a")["root"] = "new";
        check(database.commit(update), "update commits");
        stale.edit("workspaces", "b")["root"] = "must not commit";
        check(!database.commit(stale), "read/write conflict rejects whole transaction");
        auto scan = database.transaction();
        (void)scan.at("workspaces");
        auto insert = database.transaction();
        insert.edit("workspaces", "c") = {{"root", "inserted"}};
        check(database.commit(insert), "insert commits");
        check(!database.commit(scan), "table scan detects phantom insert");
        auto state = database.state();
        check(state["workspaces"]["b"]["root"] == "second", "failed transaction has no partial writes");
        check(state["events"][0]["offset"] == 0 && state["events"][1]["offset"] == 1,
              "concurrent events receive ordered offsets");
    }
    Database reopened(directory.path);
    check(reopened.state()["workspaces"]["a"]["root"] == "new", "transaction recovery");
    check(reopened.state()["partitions"]["events"].size() == 2, "partition recovery");
}
void crypto() {
    check(axon::hash("") == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "BLAKE3 empty vector");
    check(axon::hash("abc") == "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85", "BLAKE3 abc vector");
    auto seed = axon::randomHex(32);
    auto key = axon::publicKey(seed);
    auto signature = axon::sign(seed, "message");
    check(axon::verify(key, "message", signature), "Ed25519 valid signature");
    check(!axon::verify(key, "tampered", signature), "Ed25519 tamper rejected");
}
void storage() {
    Directory directory;
    Store store(directory.path);
    std::string data;
    for (int i = 0; i < 8192; ++i)
        data += axon::unhex(axon::hash(std::to_string(i)));
    auto first = store.putBlob(data);
    check(store.blob(first) == data, "chunked blob roundtrip");
    auto changed = data;
    changed.replace(10000, 20, "an inserted modification");
    auto second = store.putBlob(changed);
    check(store.blob(second) == changed, "edited blob roundtrip");
    auto original_chunks = store.node(first).at("chunks");
    auto changed_chunks = store.node(second).at("chunks");
    std::size_t shared = 0;
    for (auto const &chunk : original_chunks)
        if (std::find(changed_chunks.begin(), changed_chunks.end(), chunk) != changed_chunks.end())
            ++shared;
    check(shared + 3 >= original_chunks.size(), "FastCDC edit locality");
    auto root = store.empty();
    Json entry{{"kind", "file"}, {"hash", first}, {"exec", false}, {"size", data.size()}};
    auto a = store.set(store.set(root, "a/file", entry), "b/file", entry);
    auto b = store.set(store.set(root, "b/file", entry), "a/file", entry);
    check(a == b, "canonical Merkle tree");
    check(store.set(store.set(a, "a", nullptr), "b", nullptr) == root, "canonical empty tree");
    auto listing = store.readHash(a, "a/");
    auto updated =
        store.set(a, "a/file", Json{{"kind", "file"}, {"hash", second}, {"exec", false}, {"size", changed.size()}});
    check(listing == store.readHash(updated, "a/"), "listing reads ignore file content changes");
    auto object = store.put("integrity");
    check(store.get(object) == "integrity", "cache populated before corruption");
    axon::writeFile(store.directory() / object.substr(0, 2) / object.substr(2), "tamper");
    bool rejected = false;
    try {
        (void)store.get(object);
    } catch (std::exception const &) {
        rejected = true;
    }
    check(rejected, "CAS corruption detected");
}
void graphCache() {
    Directory directory;
    Store store(directory.path);
    auto root = store.empty();
    auto first = GraphCache::get(store, root);
    check(first == GraphCache::get(store, root), "graph cache hit");
    std::weak_ptr<Graph> old = first;
    first.reset();
    for (int i = 0; i < 65; ++i) {
        auto data = std::to_string(i);
        root = store.set(root, "input", {{"kind", "file"}, {"hash", store.putBlob(data)}, {"size", data.size()}});
        (void)GraphCache::get(store, root);
    }
    check(old.expired(), "least recently used graph evicted");
    Directory other;
    Store other_store(other.path);
    auto cached = GraphCache::get(store, root);
    bool missing = false;
    try {
        (void)GraphCache::get(other_store, root);
    } catch (std::exception const &) {
        missing = true;
    }
    check(missing, "graph cache does not cross repository boundaries");
    GraphCache::clear();
    check(cached->targets().empty(), "eviction preserves active graph users");
}
void policyValidation() {
    validatePolicy({{"rules", {{{"name", "docs"}, {"when", {{"any_path", {"docs/**"}}}}, {"waive_review", true}}}}});
    for (auto const &invalid : std::vector<Json>{{{"ruels", Json::array()}},
                                                 {{"limits", {{"landings_per_minute", -1}}}},
                                                 {{"rules", {{{"name", "bad"}, {"when", {{"any_path", "docs/**"}}}}}}},
                                                 {{"defaults", {{"agent", {{"review", "yes"}}}}}},
                                                 {{"rules", {{{"name", "x"}}, {{"name", "x"}}}}}}) {
        bool rejected = false;
        try {
            validatePolicy(invalid);
        } catch (std::exception const &) {
            rejected = true;
        }
        check(rejected, "invalid policy rejected at configuration time");
    }
}
void journalCompaction() {
    Directory directory;
    Json expected{{"retained", "value"}, {"counter", 99}};
    {
        Database database(directory.path);
        for (int i = 0; i < 100; ++i)
            database.commit({{"retained", "value"}, {"counter", i}});
        auto before = std::filesystem::file_size(directory.path / "journal.jsonl");
        database.compact();
        check(std::filesystem::file_size(directory.path / "journal.jsonl") < before, "compaction shrinks journal");
        check(database.state() == expected, "compaction preserves live state");
    }
    {
        Database database(directory.path);
        check(database.state() == expected, "compacted journal recovers");
        database.commitPatch(Json::array({{{"op", "replace"}, {"path", "/counter"}, {"value", 100}}}));
    }
    Database database(directory.path);
    expected["counter"] = 100;
    check(database.state() == expected, "journal appends after checkpoint");
}
void journal() {
    Directory directory;
    {
        Database database(directory.path);
        database.commit({{"one", 1}});
        database.commit({{"one", 2}, {"two", "kept"}});
    }
    auto journal = directory.path / "journal.jsonl";
    axon::writeFile(journal, axon::readFile(journal) + "{partial");
    {
        Database database(directory.path);
        check(database.state().at("one") == 2, "torn tail recovery");
        database.commit({{"one", 3}});
    }
    {
        Database database(directory.path);
        check(database.state() == Json{{"one", 3}}, "write after tail recovery");
    }
    auto text = axon::readFile(journal);
    auto position = text.find("\"hash\":\"");
    check(position != std::string::npos, "journal hash present");
    text[position + 8] = text[position + 8] == '0' ? '1' : '0';
    axon::writeFile(journal, text);
    bool rejected = false;
    try {
        Database database(directory.path);
    } catch (std::exception const &) {
        rejected = true;
    }
    check(rejected, "complete corrupt journal record rejected");
}
// A file-size limit makes the journal append fail partway through a record.
void journal_failure() {
    Directory directory;
    auto journal = directory.path / "journal.jsonl";
    {
        Database database(directory.path);
        database.commit({{"one", 1}});
        rlimit original{};
        check(::getrlimit(RLIMIT_FSIZE, &original) == 0, "read file size limit");
        auto previous_handler = std::signal(SIGXFSZ, SIG_IGN);
        rlimit limited = original;
        limited.rlim_cur = std::filesystem::file_size(journal) + 16;
        check(::setrlimit(RLIMIT_FSIZE, &limited) == 0, "set file size limit");
        bool failed = false;
        try {
            database.commit({{"one", 2}, {"lost", std::string(4096, 'x')}});
        } catch (std::exception const &) {
            failed = true;
        }
        check(::setrlimit(RLIMIT_FSIZE, &original) == 0, "restore file size limit");
        std::signal(SIGXFSZ, previous_handler);
        check(failed, "failed journal append reported");
        check(database.state() == Json{{"one", 1}}, "failed append not visible in memory");
        database.commit({{"one", 3}});
        check(database.state() == Json{{"one", 3}}, "commit after failed append");
    }
    Database database(directory.path);
    check(database.state() == Json{{"one", 3}}, "journal intact after failed append");
}
void journal_group_commit() {
    Directory directory;
    constexpr int writers = 8;
    constexpr int commits = 25;
    {
        Database database(directory.path);
        std::vector<std::thread> threads;
        for (int w = 0; w < writers; ++w)
            threads.emplace_back([&database, w] {
                for (int c = 0; c < commits; ++c) {
                    auto key = "/" + std::to_string(w) + "-" + std::to_string(c);
                    database.commitPatch(Json::array({{{"op", "add"}, {"path", key}, {"value", c}}}));
                }
            });
        for (auto &thread : threads)
            thread.join();
        check(database.state().size() == writers * commits, "concurrent commits visible");
    }
    Database database(directory.path);
    check(database.state().size() == writers * commits, "concurrent commits durable");
}
void auth() {
    Directory directory;
    auto seed = axon::randomHex(32);
    Repository repo(directory.path);
    repo.initialize("human:test", axon::publicKey(seed));
    auto envelope = axon::signedRequest({{"command", "whoami"}}, "human:test", seed);
    check(repo.request(envelope).has_value(), "authenticated request accepted");
    check(!repo.request(envelope), "replay rejected");
    auto altered = axon::signedRequest({{"command", "whoami"}}, "human:test", seed);
    altered["payload"]["command"] = "lines";
    check(!repo.request(altered), "altered request rejected");
    auto wrong = axon::signedRequest({{"command", "whoami"}}, "human:test", axon::randomHex(32));
    check(!repo.request(wrong), "unregistered signing key rejected");
    auto expired = axon::signedRequest({{"command", "whoami"}}, "human:test", seed);
    expired["created"] = axon::now() - 600;
    expired.erase("signature");
    expired["signature"] = axon::sign(seed, expired.dump());
    check(!repo.request(expired), "expired request rejected");
}
void signedStatements() {
    Directory directory;
    auto seed = axon::randomHex(32);
    Repository repo(directory.path);
    repo.initialize("human:test", axon::publicKey(seed));
    auto agent_key = axon::publicKey(axon::randomHex(32));
    auto issued = repo.request(
        signedRequest({{"command", "agent-key"}, {"args", {"bot"}}, {"public_key", agent_key}}, "human:test", seed));
    check(issued.has_value(), "signed agent binding accepted");
    auto binding = issued->at("binding");
    auto signature = binding.at("signature").get<std::string>();
    binding.erase("id");
    binding.erase("signature");
    check(verify(publicKey(seed), binding.dump(), signature), "agent binding verifies independently");
    auto payload =
        Json{{"command", "attest"},
             {"options", {{"target", "//:test"}, {"input", hash("input")}, {"kind", "tests"}, {"result", "passed"}}}};
    auto request = signedRequest(payload, "human:test", seed);
    auto claim = repo.request(request);
    check(claim.has_value(), "standalone attestation accepted");
    auto standalone = *claim;
    auto claim_signature = standalone.at("signature").get<std::string>();
    standalone.erase("id");
    standalone.erase("signature");
    check(verify(publicKey(seed), standalone.dump(), claim_signature), "attestation verifies independently");
    auto tampered = signedRequest(payload, "human:test", seed);
    tampered["payload"]["attestation"]["result"] = "failed";
    tampered.erase("signature");
    tampered["signature"] = sign(seed, tampered.dump());
    check(!repo.request(tampered), "valid outer signature cannot hide a tampered statement");
}
void sharding() {
    Directory directory;
    Store store(directory.path);
    store.setShardMaxForTest(32);
    auto root = store.empty();
    std::string first_blob = store.putBlob("blob");
    Json file_entry{{"kind", "file"}, {"hash", first_blob}, {"exec", false}, {"size", 4}};

    auto current = root;
    for (int i = 0; i < 200; ++i) {
        current = store.set(current, "dir/f" + std::to_string(i), file_entry);
    }
    auto dir_lookup = store.lookup(current, "dir");
    check(!dir_lookup.is_null() && dir_lookup.at("kind") == "dir", "sharded dir exists");
    auto dir_node = store.node(dir_lookup.at("hash").get<std::string>());
    check(dir_node.value("type", "") == "dir_shard", "dir node is sharded");
    check(dir_node.at("count").get<std::size_t>() == 200, "shard count matches 200");

    auto listed = store.list(current, "dir");
    check(listed.size() == 200, "sharded list has 200 files");

    auto reverse_root = root;
    for (int i = 199; i >= 0; --i) {
        reverse_root = store.set(reverse_root, "dir/f" + std::to_string(i), file_entry);
    }
    check(reverse_root == current, "sharding is canonical regardless of insertion order");

    auto small = current;
    for (int i = 10; i < 200; ++i) {
        small = store.set(small, "dir/f" + std::to_string(i), nullptr);
    }
    auto small_dir = store.lookup(small, "dir");
    auto small_node = store.node(small_dir.at("hash").get<std::string>());
    check(small_node.value("type", "") != "dir_shard", "sharded dir collapsed to leaf");
    check(small_node.size() == 10, "collapsed leaf has 10 entries");
}
void workflow_and_queue() {
    Directory directory;
    auto seed = axon::randomHex(32);
    Repository repo(directory.path);
    repo.initialize("human:test", axon::publicKey(seed));

    auto req_wf = axon::signedRequest({{"command", "workflows"}}, "human:test", seed);
    auto wfs_res = repo.request(req_wf);
    check(wfs_res.has_value() && wfs_res->is_array(), "default workflows retrieved");
    check(wfs_res->at(0).at("name") == "tests", "default workflow name is tests");

    auto req_q = axon::signedRequest({{"command", "queue"}, {"options", {{"line", "trunk"}}}}, "human:test", seed);
    auto q_res = repo.request(req_q);
    check(q_res.has_value() && q_res->is_array(), "queue query succeeds");

    auto prom = repo.metricsPrometheus();
    check(prom.find("axon_landings_total") != std::string::npos, "axon_landings_total present");
    check(prom.find("axon_landings_total") != std::string::npos, "axon_landings_total present");

    auto evs = repo.eventsSince(0, "line-trunk");
    check(evs.is_array(), "eventsSince returns json array");
}
} // namespace
} // namespace axon::test
int main() {
    try {
        axon::test::symbolReadsAndMerges();
        axon::test::filesystemProtocol();
        axon::test::retention();
        axon::test::replayIds();
        axon::test::transactions();
        axon::test::crypto();
        axon::test::graphCache();
        axon::test::policyValidation();
        axon::test::journalCompaction();
        axon::test::storage();
        axon::test::sharding();
        axon::test::journal();
        axon::test::journal_failure();
        axon::test::journal_group_commit();
        axon::test::auth();
        axon::test::signedStatements();
        axon::test::workflow_and_queue();
        std::cout << "All Axon unit checks passed\n";
        return 0;
    } catch (std::exception const &error) {
        std::cerr << error.what() << '\n';
        return 1;
    }
}
