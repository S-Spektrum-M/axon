#include "filesystem.hpp"

#include <algorithm>
#include <cerrno>

namespace axon {
Json filesystemRequest(Store &store, Json &workspace, Json const &request) {
    auto path = cleanPath(request.value("path", ""), true);
    auto action = request.at("action").get<std::string>();
    auto root = workspace.at("root").get<std::string>();
    auto entry = store.lookup(root, path);
    auto read = action == "list" ? path + "/" : path;
    if (!read.empty() &&
        std::find(workspace["reads"].begin(), workspace["reads"].end(), Json(read)) == workspace["reads"].end())
        workspace["reads"].push_back(read);
    auto fail = [](int error) -> Json { return {{"errno", error}}; };
    if (action == "stat")
        return entry.is_null() ? fail(ENOENT) : entry;
    if (action == "list")
        return entry.is_null() ? fail(ENOENT) : entry.at("kind") != "dir" ? fail(ENOTDIR) : store.list(root, path);
    if (action == "read") {
        if (entry.is_null())
            return fail(ENOENT);
        if (entry.at("kind") == "dir")
            return fail(EISDIR);
        auto bytes = store.blob(entry.at("hash").get<std::string>());
        auto offset = request.value("offset", std::size_t{0});
        auto size = request.value("size", bytes.size());
        return {
            {"bytes", hex(offset < bytes.size() ? std::string_view(bytes).substr(offset, size) : std::string_view{})}};
    }
    if (path.empty())
        return fail(EBUSY);
    auto parent = store.lookup(root, Path(path).parent_path().generic_string());
    if (parent.is_null() || parent.at("kind") != "dir")
        return fail(ENOENT);
    if (action == "create" || action == "mkdir" || action == "symlink") {
        if (!entry.is_null())
            return fail(EEXIST);
        if (action == "mkdir")
            entry = {{"kind", "dir"}, {"hash", store.empty()}, {"explicit", true}};
        else {
            auto bytes = action == "symlink" ? request.at("target").get<std::string>() : "";
            entry = {{"kind", action == "symlink" ? "link" : "file"},
                     {"hash", store.putBlob(bytes)},
                     {"exec", request.value("exec", false)},
                     {"size", bytes.size()}};
        }
        root = store.set(root, path, entry);
    } else if (action == "write" || action == "setattr") {
        if (entry.is_null())
            return fail(ENOENT);
        if (entry.at("kind") != "file")
            return fail(EINVAL);
        auto bytes = store.blob(entry.at("hash").get<std::string>());
        constexpr std::size_t limit = 32 * 1024 * 1024;
        if (action == "write") {
            auto offset = request.at("offset").get<std::size_t>();
            auto content = unhex(request.at("bytes").get<std::string>());
            if (offset > limit || content.size() > limit - offset)
                return fail(EFBIG);
            bytes.resize(std::max(bytes.size(), offset + content.size()), '\0');
            bytes.replace(offset, content.size(), content);
        } else {
            if (request.contains("size")) {
                auto size = request.at("size").get<std::size_t>();
                if (size > limit)
                    return fail(EFBIG);
                bytes.resize(size, '\0');
            }
            if (request.contains("exec"))
                entry["exec"] = request.at("exec");
        }
        entry["hash"] = store.putBlob(bytes);
        entry["size"] = bytes.size();
        root = store.set(root, path, entry);
    } else if (action == "unlink" || action == "rmdir") {
        if (entry.is_null())
            return fail(ENOENT);
        if (action == "rmdir" && entry.at("kind") != "dir")
            return fail(ENOTDIR);
        if (action == "unlink" && entry.at("kind") == "dir")
            return fail(EISDIR);
        if (action == "rmdir" && !store.list(root, path).empty())
            return fail(ENOTEMPTY);
        root = store.set(root, path, nullptr);
    } else if (action == "rename") {
        if (entry.is_null())
            return fail(ENOENT);
        auto destination = cleanPath(request.at("destination").get<std::string>());
        if (destination == path)
            return entry;
        if (destination.starts_with(path + "/"))
            return fail(EINVAL);
        auto dest_parent = store.lookup(root, Path(destination).parent_path().generic_string());
        if (dest_parent.is_null() || dest_parent.at("kind") != "dir")
            return fail(ENOENT);
        auto previous = store.lookup(root, destination);
        if (!previous.is_null()) {
            if (request.value("noreplace", false))
                return fail(EEXIST);
            if ((previous.at("kind") == "dir") != (entry.at("kind") == "dir"))
                return fail(previous.at("kind") == "dir" ? EISDIR : ENOTDIR);
            if (previous.at("kind") == "dir" && !store.list(root, destination).empty())
                return fail(ENOTEMPTY);
        }
        workspace["reads"].push_back(destination);
        root = store.set(store.set(root, path, nullptr), destination, entry);
    } else
        return fail(ENOSYS);
    Json draft{{"op", "fs:" + action}, {"path", path}, {"created", now()}, {"root", root}};
    draft["id"] = store.put(draft.dump());
    workspace["drafts"].push_back(draft);
    workspace["root"] = root;
    return entry;
}
} // namespace axon
