#include "fuse.hpp"

#include "graph.hpp"
#include "repository.hpp"
#include "transport.hpp"

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <linux/fuse.h>
#include <poll.h>
#include <signal.h>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

namespace axon {
namespace {
class FuseError : public std::exception {
public:
    explicit FuseError(int value) : value(value) {
    }
    int value;
};
template <typename T> T unpack(std::string_view bytes) {
    if (bytes.size() < sizeof(T))
        throw FuseError(EINVAL);
    T result{};
    std::memcpy(&result, bytes.data(), sizeof(T));
    return result;
}
template <typename T> std::string pack(T const &value) {
    return {reinterpret_cast<char const *>(&value), sizeof(value)};
}
std::string name(std::string_view bytes) {
    auto end = bytes.find('\0');
    if (end == std::string_view::npos)
        throw FuseError(EINVAL);
    return std::string(bytes.substr(0, end));
}
std::string child(std::string const &parent, std::string const &name) {
    if (name.empty() || name == "." || name == ".." || name.find('/') != std::string::npos)
        throw FuseError(EINVAL);
    return parent.empty() ? name : parent + "/" + name;
}
fuse_attr attr(Json const &entry, std::uint64_t inode) {
    fuse_attr result{};
    result.ino = inode;
    auto kind = entry.at("kind").get<std::string>();
    result.mode = kind == "dir"    ? S_IFDIR | 0700U
                  : kind == "link" ? S_IFLNK | 0777U
                                   : S_IFREG | (entry.value("exec", false) ? 0700U : 0600U);
    result.nlink = kind == "dir" ? 2U : 1U;
    result.uid = ::getuid();
    result.gid = ::getgid();
    result.size = entry.value("size", std::uint64_t{0});
    result.blocks = (result.size + 511) / 512;
    result.blksize = 4096;
    auto mtime = entry.value("mtime_ns", std::uint64_t{0});
    auto atime = entry.value("atime_ns", mtime);
    result.mtime = result.ctime = mtime / 1000000000;
    result.mtimensec = result.ctimensec = static_cast<std::uint32_t>(mtime % 1000000000);
    result.atime = atime / 1000000000;
    result.atimensec = static_cast<std::uint32_t>(atime % 1000000000);
    return result;
}
std::string entryReply(Json const &entry, std::uint64_t inode) {
    fuse_entry_out result{};
    result.nodeid = inode;
    result.generation = 1;
    result.attr = attr(entry, inode);
    return pack(result);
}
volatile sig_atomic_t mount_stopped = 0;
void stopMount(int) {
    mount_stopped = 1;
}
} // namespace
FuseSession::FuseSession(std::function<Json(Json)> rpc) : rpc_(std::move(rpc)) {
}
std::uint64_t FuseSession::inode(std::string const &path) {
    if (auto found = inodes_.find(path); found != inodes_.end())
        return found->second;
    auto id = next_++;
    paths_[id] = path;
    inodes_[path] = id;
    return id;
}
Json FuseSession::call(std::string_view action, std::string const &path, Json extra) {
    extra["action"] = action;
    extra["path"] = path;
    auto result = rpc_(extra);
    if (result.is_object() && result.contains("errno"))
        throw FuseError(result.at("errno").get<int>());
    if (result.is_object() && result.contains("kind")) {
        auto fingerprint = hash(result.dump());
        auto &metadata = metadata_[path];
        if (metadata.fingerprint != fingerprint || action == "write") {
            auto timestamp = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                            std::chrono::system_clock::now().time_since_epoch())
                                                            .count());
            metadata = {fingerprint, timestamp, timestamp};
        }
        result["mtime_ns"] = metadata.mtime;
        result["atime_ns"] = metadata.atime;
    }
    return result;
}
std::string FuseSession::dispatch(std::string_view packet) {
    auto header = unpack<fuse_in_header>(packet);
    fuse_out_header out{};
    out.unique = header.unique;
    std::string body;
    try {
        if (header.len != packet.size())
            throw FuseError(EINVAL);
        auto input = packet.substr(sizeof(header));
        if (header.opcode == FUSE_FORGET || header.opcode == FUSE_BATCH_FORGET || header.opcode == FUSE_DESTROY)
            return {};
        if (header.opcode == FUSE_INIT) {
            // Negotiate the fixed 7.31 layout, independent of the host header version.
            if (input.size() < 16)
                throw FuseError(EINVAL);
            auto major = unpack<std::uint32_t>(input);
            auto minor = unpack<std::uint32_t>(input.substr(4));
            if (major != 7 || minor < 23)
                throw FuseError(EPROTO);
            fuse_init_out result{};
            result.major = 7;
            result.minor = std::min(minor, 31U);
            result.max_write = 128 * 1024;
            result.max_background = 1;
            result.time_gran = 1;
            body = pack(result).substr(0, 64);
        } else {
            auto found = paths_.find(header.nodeid);
            if (found == paths_.end())
                throw FuseError(ESTALE);
            auto path = found->second;
            switch (header.opcode) {
            case FUSE_LOOKUP: {
                auto target = child(path, name(input));
                body = entryReply(call("stat", target), inode(target));
                break;
            }
            case FUSE_GETATTR: {
                fuse_attr_out result{};
                result.attr = attr(call("stat", path), header.nodeid);
                body = pack(result);
                break;
            }
            case FUSE_SETATTR: {
                auto request = unpack<fuse_setattr_in>(input);
                if ((request.valid & FATTR_UID) && request.uid != ::getuid())
                    throw FuseError(EPERM);
                if ((request.valid & FATTR_GID) && request.gid != ::getgid())
                    throw FuseError(EPERM);
                Json extra = Json::object();
                if (request.valid & FATTR_SIZE)
                    extra["size"] = request.size;
                if (request.valid & FATTR_MODE)
                    extra["exec"] = (request.mode & 0111U) != 0;
                fuse_attr_out result{};
                auto entry = extra.empty() ? call("stat", path) : call("setattr", path, extra);
                auto timestamp = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                                std::chrono::system_clock::now().time_since_epoch())
                                                                .count());
                auto &metadata = metadata_.at(path);
                if (request.valid & FATTR_MTIME)
                    metadata.mtime = request.mtime * 1000000000 + request.mtimensec;
                if (request.valid & FATTR_MTIME_NOW)
                    metadata.mtime = timestamp;
                if (request.valid & FATTR_ATIME)
                    metadata.atime = request.atime * 1000000000 + request.atimensec;
                if (request.valid & FATTR_ATIME_NOW)
                    metadata.atime = timestamp;
                entry["mtime_ns"] = metadata.mtime;
                entry["atime_ns"] = metadata.atime;
                result.attr = attr(entry, header.nodeid);
                body = pack(result);
                break;
            }
            case FUSE_OPEN:
            case FUSE_OPENDIR: {
                auto request = unpack<fuse_open_in>(input);
                auto entry = call("stat", path);
                bool directory = entry.at("kind") == "dir";
                if (directory != (header.opcode == FUSE_OPENDIR))
                    throw FuseError(directory ? EISDIR : ENOTDIR);
                if (!directory && (request.flags & O_TRUNC))
                    (void)call("setattr", path, {{"size", 0}});
                fuse_open_out result{};
                result.fh = header.nodeid;
                result.open_flags = directory ? 0U : FOPEN_DIRECT_IO;
                body = pack(result);
                break;
            }
            case FUSE_CREATE: {
                auto request = unpack<fuse_create_in>(input);
                auto target = child(path, name(input.substr(sizeof(request))));
                auto entry = call("create", target, {{"exec", (request.mode & 0111U) != 0}});
                auto id = inode(target);
                fuse_open_out result{};
                result.fh = id;
                result.open_flags = FOPEN_DIRECT_IO;
                body = entryReply(entry, id) + pack(result);
                break;
            }
            case FUSE_MKDIR: {
                auto request = unpack<fuse_mkdir_in>(input);
                auto target = child(path, name(input.substr(sizeof(request))));
                body = entryReply(call("mkdir", target), inode(target));
                break;
            }
            case FUSE_SYMLINK: {
                auto filename = name(input);
                auto target = child(path, filename);
                auto link = name(input.substr(filename.size() + 1));
                body = entryReply(call("symlink", target, {{"target", link}}), inode(target));
                break;
            }
            case FUSE_READLINK:
                body = unhex(call("read", path).at("bytes").get<std::string>());
                break;
            case FUSE_READ: {
                auto request = unpack<fuse_read_in>(input);
                body = unhex(call("read", path, {{"offset", request.offset}, {"size", request.size}})
                                 .at("bytes")
                                 .get<std::string>());
                break;
            }
            case FUSE_WRITE: {
                auto request = unpack<fuse_write_in>(input);
                if (input.size() - sizeof(request) != request.size)
                    throw FuseError(EINVAL);
                (void)call("write", path, {{"offset", request.offset}, {"bytes", hex(input.substr(sizeof(request)))}});
                fuse_write_out result{};
                result.size = request.size;
                body = pack(result);
                break;
            }
            case FUSE_READDIR: {
                auto request = unpack<fuse_read_in>(input);
                auto entries = call("list", path);
                std::vector<std::pair<std::string, Json>> values{{".", {{"kind", "dir"}}}, {"..", {{"kind", "dir"}}}};
                for (auto const &[filename, entry] : entries.items())
                    values.emplace_back(filename, entry);
                for (auto i = request.offset; i < values.size(); ++i) {
                    auto const &[filename, entry] = values[i];
                    auto target = filename == "."    ? path
                                  : filename == ".." ? Path(path).parent_path().generic_string()
                                                     : child(path, filename);
                    fuse_dirent dirent{};
                    dirent.ino = inode(target);
                    dirent.off = i + 1;
                    dirent.namelen = static_cast<std::uint32_t>(filename.size());
                    dirent.type = attr(entry, dirent.ino).mode >> 12U;
                    auto packed = pack(dirent).substr(0, FUSE_NAME_OFFSET) + filename;
                    packed.resize((packed.size() + 7) & ~std::size_t{7}, '\0');
                    if (body.size() + packed.size() > request.size)
                        break;
                    body += packed;
                }
                break;
            }
            case FUSE_UNLINK:
            case FUSE_RMDIR:
                (void)call(header.opcode == FUSE_UNLINK ? "unlink" : "rmdir", child(path, name(input)));
                break;
            case FUSE_RENAME:
            case FUSE_RENAME2: {
                std::uint64_t directory;
                std::uint32_t flags = 0;
                if (header.opcode == FUSE_RENAME2) {
                    auto request = unpack<fuse_rename2_in>(input);
                    directory = request.newdir;
                    flags = request.flags;
                    input.remove_prefix(sizeof(request));
                } else {
                    auto request = unpack<fuse_rename_in>(input);
                    directory = request.newdir;
                    input.remove_prefix(sizeof(request));
                }
                if (flags & ~1U)
                    throw FuseError(EINVAL);
                auto old_name = name(input);
                auto source = child(path, old_name);
                auto destination = child(paths_.at(directory), name(input.substr(old_name.size() + 1)));
                (void)call("rename", source, {{"destination", destination}, {"noreplace", flags == 1}});
                for (auto &[id, old_path] : paths_) {
                    if (old_path == source || old_path.starts_with(source + "/")) {
                        inodes_.erase(old_path);
                        old_path = destination + old_path.substr(source.size());
                        inodes_[old_path] = id;
                    }
                }
                break;
            }
            case FUSE_STATFS: {
                fuse_statfs_out result{};
                result.st.bsize = 4096;
                result.st.frsize = 4096;
                result.st.namelen = 255;
                result.st.blocks = result.st.bfree = result.st.bavail = 1ULL << 28U;
                body = pack(result);
                break;
            }
            case FUSE_ACCESS:
                (void)call("stat", path);
                break;
            case FUSE_FLUSH:
            case FUSE_FSYNC:
            case FUSE_FSYNCDIR:
            case FUSE_RELEASE:
            case FUSE_RELEASEDIR:
                break; // Every write RPC has already waited for journal fsync.
            default:
                throw FuseError(ENOSYS);
            }
        }
    } catch (FuseError const &error) {
        out.error = -error.value;
        body.clear();
    } catch (std::exception const &) {
        out.error = -EIO;
        body.clear();
    }
    out.len = static_cast<std::uint32_t>(sizeof(out) + body.size());
    return pack(out) + body;
}
void mountWorkspace(std::string_view workspace, Path const &mountpoint, Json const &config, std::string_view seed) {
    auto point = std::filesystem::canonical(mountpoint);
    if (!std::filesystem::is_directory(point) || !std::filesystem::is_empty(point))
        throw std::runtime_error("mountpoint must be an empty directory");
    if (!std::filesystem::exists("/dev/fuse"))
        throw std::runtime_error("FUSE requires /dev/fuse and fusermount3 on this host");
    auto rpc = [&](Json request) {
        request["command"] = "fs";
        request["args"] = {workspace};
        return remoteRequest(config.at("server").get<std::string>(),
                             signedRequest(request, config.at("principal").get<std::string>(), seed));
    };
    auto root = rpc({{"action", "stat"}, {"path", ""}});
    if (root.contains("errno"))
        throw std::runtime_error("cannot access workspace root");
    int sockets[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets) != 0)
        throw std::runtime_error("FUSE socketpair failed");
    Descriptor parent(sockets[0]);
    {
        Descriptor child_socket(sockets[1]);
        auto pid = ::fork();
        if (pid < 0)
            throw std::runtime_error("FUSE fork failed");
        if (pid == 0) {
            ::close(parent.get());
            if (::dup2(child_socket.get(), 3) < 0)
                ::_exit(126);
            (void)::fcntl(3, F_SETFD, 0);
            (void)::setenv("_FUSE_COMMFD", "3", 1);
            ::execlp("fusermount3",
                     "fusermount3",
                     "-o",
                     "rw,nosuid,nodev,fsname=axon,subtype=axon,default_permissions",
                     "--",
                     point.c_str(),
                     static_cast<char *>(nullptr));
            ::_exit(127);
        }
        int status = 0;
        while (::waitpid(pid, &status, 0) < 0)
            if (errno != EINTR)
                throw std::runtime_error("FUSE helper wait failed");
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
            throw std::runtime_error("fusermount3 failed");
    }
    alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(int))> control{};
    char byte = 0;
    iovec vector{&byte, 1};
    msghdr message{};
    message.msg_iov = &vector;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();
    if (::recvmsg(parent.get(), &message, MSG_CMSG_CLOEXEC) <= 0)
        throw std::runtime_error("FUSE helper did not return a device descriptor");
    auto ancillary = CMSG_FIRSTHDR(&message);
    if (!ancillary || ancillary->cmsg_level != SOL_SOCKET || ancillary->cmsg_type != SCM_RIGHTS ||
        ancillary->cmsg_len != CMSG_LEN(sizeof(int)))
        throw std::runtime_error("invalid FUSE device descriptor");
    int device_fd;
    std::memcpy(&device_fd, CMSG_DATA(ancillary), sizeof(device_fd));
    Descriptor device(device_fd);
    struct sigaction action{}, old_int{}, old_term{};
    action.sa_handler = stopMount;
    ::sigemptyset(&action.sa_mask);
    ::sigaction(SIGINT, &action, &old_int);
    ::sigaction(SIGTERM, &action, &old_term);
    mount_stopped = 0;
    FuseSession session(rpc);
    std::array<char, 256 * 1024> buffer{};
    while (!mount_stopped) {
        pollfd poller{device.get(), POLLIN, 0};
        if (::poll(&poller, 1, 250) <= 0)
            continue;
        auto size = ::read(device.get(), buffer.data(), buffer.size());
        if (size <= 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        auto response = session.dispatch(std::string_view(buffer.data(), static_cast<std::size_t>(size)));
        if (!response.empty() &&
            ::write(device.get(), response.data(), response.size()) != static_cast<ssize_t>(response.size()))
            break;
    }
    std::vector<std::string> unmount{"fusermount3", "-u", "--", point.string()};
    (void)runProcess(unmount, "/");
    ::sigaction(SIGINT, &old_int, nullptr);
    ::sigaction(SIGTERM, &old_term, nullptr);
}
} // namespace axon
