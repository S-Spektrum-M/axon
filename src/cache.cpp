#include "cache.hpp"

#include <arpa/inet.h>
#include <array>
#include <atomic>
#include <cctype>
#include <charconv>
#include <condition_variable>
#include <curl/curl.h>
#include <functional>
#include <iostream>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <poll.h>
#include <queue>
#include <signal.h>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace axon {
namespace {
constexpr std::size_t MAX_BODY = 64 * 1024 * 1024;
constexpr std::size_t MAX_HEADER = 16 * 1024;
volatile sig_atomic_t cache_stopped = 0;

void onStop(int) {
    cache_stopped = 1;
}

void require(bool condition, std::string_view message) {
    if (!condition)
        throw std::runtime_error(std::string(message));
}

void sendAll(int fd, std::string_view data) {
    while (!data.empty()) {
        auto n = ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR)
            continue;
        require(n > 0, "socket write failed");
        data.remove_prefix(static_cast<std::size_t>(n));
    }
}

std::size_t curlWriteCallback(char *data, std::size_t size, std::size_t count, void *context) {
    auto &output = *static_cast<std::string *>(context);
    auto bytes = size * count;
    if (output.size() + bytes > MAX_BODY)
        return 0;
    output.append(data, bytes);
    return bytes;
}

struct HttpResponse {
    long status_code = 0;
    std::string content_type = "application/octet-stream";
    std::string body;
};

HttpResponse fetchUpstream(std::string_view upstream_url,
                           std::string_view path,
                           std::string_view method = "GET",
                           std::string_view post_body = "",
                           std::string_view content_type = "application/json") {
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
    if (!curl)
        throw std::runtime_error("curl init failed");
    auto full_url = std::string(upstream_url);
    while (full_url.ends_with('/'))
        full_url.pop_back();
    if (!path.starts_with('/'))
        full_url += '/';
    full_url += path;

    HttpResponse resp;
    curl_easy_setopt(curl.get(), CURLOPT_URL, full_url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, curlWriteCallback);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &resp.body);
    curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, 600L);
    curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);

    struct curl_slist *headers = nullptr;
    if (method == "POST") {
        curl_easy_setopt(curl.get(), CURLOPT_POST, 1L);
        curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, post_body.data());
        curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(post_body.size()));
        std::string ct_hdr = "Content-Type: " + std::string(content_type);
        headers = curl_slist_append(headers, ct_hdr.c_str());
        curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers);
    }

    auto res = curl_easy_perform(curl.get());
    if (headers)
        curl_slist_free_all(headers);

    if (res != CURLE_OK)
        return resp;

    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &resp.status_code);
    char *ct = nullptr;
    curl_easy_getinfo(curl.get(), CURLINFO_CONTENT_TYPE, &ct);
    if (ct)
        resp.content_type = ct;

    return resp;
}

class CacheThreadPool {
public:
    explicit CacheThreadPool(std::size_t threads = 16) {
        for (std::size_t i = 0; i < threads; ++i) {
            workers_.emplace_back([this]() {
                while (true) {
                    std::function<void()> task;
                    {
                        std::unique_lock lock(mutex_);
                        cv_.wait(lock, [this]() { return stopped_ || !tasks_.empty(); });
                        if (stopped_ && tasks_.empty())
                            return;
                        task = std::move(tasks_.front());
                        tasks_.pop();
                    }
                    task();
                }
            });
        }
    }
    ~CacheThreadPool() {
        {
            std::lock_guard lock(mutex_);
            stopped_ = true;
        }
        cv_.notify_all();
        for (auto &w : workers_) {
            if (w.joinable())
                w.join();
        }
    }
    void push(std::function<void()> task) {
        {
            std::lock_guard lock(mutex_);
            tasks_.push(std::move(task));
        }
        cv_.notify_one();
    }

private:
    std::vector<std::jthread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool stopped_ = false;
};

void handleCacheClient(int fd,
                       Store &store,
                       std::string const &upstream,
                       std::atomic<std::int64_t> &hits,
                       std::atomic<std::int64_t> &misses) {
    timeval timeout{10, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    std::string bytes;
    std::array<char, 8192> buffer{};
    auto receive = [&bytes, &buffer, fd]() {
        auto n = ::recv(fd, buffer.data(), buffer.size(), 0);
        require(n > 0, "incomplete HTTP request");
        bytes.append(buffer.data(), static_cast<std::size_t>(n));
    };
    while (bytes.find("\r\n\r\n") == std::string::npos) {
        require(bytes.size() <= MAX_HEADER, "HTTP header too large");
        receive();
    }
    auto end = bytes.find("\r\n\r\n");
    require(end <= MAX_HEADER, "HTTP header too large");
    std::istringstream headers(bytes.substr(0, end));
    std::string req_line;
    std::getline(headers, req_line);
    if (!req_line.empty() && req_line.back() == '\r')
        req_line.pop_back();

    std::istringstream req_stream(req_line);
    std::string method, path, proto;
    req_stream >> method >> path >> proto;

    std::size_t length = 0;
    std::string content_type = "application/json";
    std::string hdr_line;
    while (std::getline(headers, hdr_line)) {
        if (!hdr_line.empty() && hdr_line.back() == '\r')
            hdr_line.pop_back();
        auto colon = hdr_line.find(':');
        if (colon == std::string::npos)
            continue;
        auto name = hdr_line.substr(0, colon);
        for (char &c : name)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (name == "content-length") {
            auto val = hdr_line.substr(colon + 1);
            auto first = val.find_first_not_of(' ');
            if (first != std::string::npos)
                (void)std::from_chars(val.data() + first, val.data() + val.size(), length);
        } else if (name == "content-type") {
            auto val = hdr_line.substr(colon + 1);
            auto first = val.find_first_not_of(' ');
            if (first != std::string::npos)
                content_type = val.substr(first);
        }
    }

    auto body_start = end + 4;
    while (bytes.size() - body_start < length)
        receive();
    std::string req_body = bytes.substr(body_start, length);

    // 1. /cache/stats
    if (path == "/cache/stats") {
        std::string stats_body =
            "hits " + std::to_string(hits.load()) + "\nmisses " + std::to_string(misses.load()) + "\n";
        auto resp_hdr = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: " +
                        std::to_string(stats_body.size()) + "\r\n\r\n";
        sendAll(fd, resp_hdr);
        sendAll(fd, stats_body);
        return;
    }

    // 2. /cas/<hash> or /cas/<ns>/<hash>
    if (method == "GET" && path.starts_with("/cas/")) {
        auto sub = path.substr(5);
        auto slash = sub.rfind('/');
        auto hash_str = (slash == std::string::npos) ? sub : sub.substr(slash + 1);
        if (hash_str.size() != 64 || hash_str.find_first_not_of("0123456789abcdef") != std::string::npos) {
            sendAll(fd, "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
            return;
        }
        if (store.has(hash_str)) {
            hits.fetch_add(1, std::memory_order_relaxed);
            auto blob = store.blob(hash_str);
            auto resp_hdr = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                            "Cache-Control: public, max-age=31536000, immutable\r\n"
                            "X-Axon-Cache: hit\r\n"
                            "Connection: close\r\nContent-Length: " +
                            std::to_string(blob.size()) + "\r\n\r\n";
            sendAll(fd, resp_hdr);
            sendAll(fd, blob);
            return;
        }

        // Cache miss -> fetch from upstream
        auto upstream_resp = fetchUpstream(upstream, path, "GET");
        if (upstream_resp.status_code == 200) {
            misses.fetch_add(1, std::memory_order_relaxed);
            // Blob IDs hash canonical chunk manifests, not the raw response body.
            if (store.putBlob(upstream_resp.body) != hash_str) {
                sendAll(fd, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
                return;
            }
            auto resp_hdr = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                            "Cache-Control: public, max-age=31536000, immutable\r\n"
                            "X-Axon-Cache: miss\r\n"
                            "Connection: close\r\nContent-Length: " +
                            std::to_string(upstream_resp.body.size()) + "\r\n\r\n";
            sendAll(fd, resp_hdr);
            sendAll(fd, upstream_resp.body);
            return;
        }

        auto err_hdr = "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        sendAll(fd, err_hdr);
        return;
    }

    // 3. Fallback: Proxy request to upstream
    auto upstream_resp = fetchUpstream(upstream, path, method, req_body, content_type);
    auto status = upstream_resp.status_code > 0 ? upstream_resp.status_code : 502;
    auto status_text = (status == 200) ? "OK" : (status == 404 ? "Not Found" : "Error");
    auto resp_hdr =
        "HTTP/1.1 " + std::to_string(status) + " " + status_text + "\r\nContent-Type: " + upstream_resp.content_type +
        "\r\nConnection: close\r\nContent-Length: " + std::to_string(upstream_resp.body.size()) + "\r\n\r\n";
    sendAll(fd, resp_hdr);
    sendAll(fd, upstream_resp.body);
}
} // namespace

void serveCache(CacheConfig const &config) {
    auto colon = config.listen.rfind(':');
    require(colon != std::string::npos, "listen address must be host:port");
    auto host = config.listen.substr(0, colon);
    auto port = config.listen.substr(colon + 1);

    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    addrinfo *raw = nullptr;
    require(::getaddrinfo(host.empty() ? nullptr : host.c_str(), port.c_str(), &hints, &raw) == 0,
            "invalid listen address");
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> info(raw, freeaddrinfo);
    Descriptor listener(::socket(info->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0));
    int enabled = 1;
    ::setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    require(::bind(listener.get(), info->ai_addr, info->ai_addrlen) == 0, "bind failed");
    require(::listen(listener.get(), 128) == 0, "listen failed");

    struct sigaction action{};
    action.sa_handler = onStop;
    ::sigemptyset(&action.sa_mask);
    ::sigaction(SIGINT, &action, nullptr);
    ::sigaction(SIGTERM, &action, nullptr);

    Store store(config.dir.empty() ? (configDirectory() / "cache") : config.dir);
    std::atomic<std::int64_t> hits{0};
    std::atomic<std::int64_t> misses{0};

    std::cerr << "axon cache " << config.listen << " -> " << config.upstream << " (dir "
              << (config.dir.empty() ? (configDirectory() / "cache") : config.dir).string() << ")\n";

    CacheThreadPool pool(16);
    while (!cache_stopped) {
        pollfd event{listener.get(), POLLIN, 0};
        if (::poll(&event, 1, 250) <= 0)
            continue;
        auto accepted = ::accept4(listener.get(), nullptr, nullptr, SOCK_CLOEXEC);
        if (accepted < 0)
            continue;
        pool.push([accepted, &store, upstream = config.upstream, &hits, &misses]() {
            Descriptor connection(accepted);
            try {
                handleCacheClient(connection.get(), store, upstream, hits, misses);
            } catch (...) {
            }
        });
    }
}
} // namespace axon
