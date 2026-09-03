#include "transport.hpp"

#include <arpa/inet.h>
#include <array>
#include <cctype>
#include <charconv>
#include <condition_variable>
#include <cstdlib>
#include <curl/curl.h>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <openssl/ssl.h>
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
volatile sig_atomic_t stopped = 0;
void stop(int) {
    stopped = 1;
}
void require(bool condition, std::string_view message) {
    if (!condition)
        throw std::runtime_error(std::string(message));
}
void initializeCurl() {
    struct CurlGlobal {
        CurlGlobal() {
            require(curl_global_init(CURL_GLOBAL_DEFAULT) == CURLE_OK, "curl initialization failed");
        }
        ~CurlGlobal() {
            curl_global_cleanup();
        }
    };
    static CurlGlobal global;
    (void)global;
}
struct Connection {
    int fd;
    std::unique_ptr<SSL, decltype(&SSL_free)> tls;
    Connection(int descriptor, SSL_CTX *context) : fd(descriptor), tls(context ? SSL_new(context) : nullptr, SSL_free) {
        if (context) {
            require(bool(tls), "TLS allocation failed");
            require(SSL_set_fd(tls.get(), fd) == 1 && SSL_accept(tls.get()) == 1, "TLS handshake failed");
        }
    }
    ~Connection() {
        if (tls)
            (void)SSL_shutdown(tls.get());
    }
};
void sendAll(Connection const &connection, std::string_view data) {
    while (!data.empty()) {
        auto n = connection.tls ? SSL_write(connection.tls.get(), data.data(), static_cast<int>(data.size()))
                                : ::send(connection.fd, data.data(), data.size(), MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR)
            continue;
        require(n > 0, "socket write failed");
        data.remove_prefix(static_cast<std::size_t>(n));
    }
}
void reply(Connection const &connection, int status, Json const &value) {
    auto body = value.dump();
    auto header =
        "HTTP/1.1 " + std::to_string(status) + " " + (status == 200 ? "OK" : "Error") +
        "\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: " + std::to_string(body.size()) +
        "\r\n\r\n";
    sendAll(connection, header);
    sendAll(connection, body);
}
class SubscriptionAdmission {
public:
    class Lease {
    public:
        Lease(SubscriptionAdmission &owner, std::string principal) : owner_(owner), principal_(std::move(principal)) {
            std::lock_guard lock(owner_.mutex_);
            if (owner_.total_ >= 8 || owner_.principals_[principal_] >= 2)
                return;
            ++owner_.total_;
            ++owner_.principals_[principal_];
            acquired = true;
        }
        ~Lease() {
            if (acquired) {
                std::lock_guard lock(owner_.mutex_);
                --owner_.total_;
                if (--owner_.principals_[principal_] == 0)
                    owner_.principals_.erase(principal_);
            }
        }
        Lease(Lease const &) = delete;
        Lease &operator=(Lease const &) = delete;
        bool acquired = false;

    private:
        SubscriptionAdmission &owner_;
        std::string principal_;
    };

private:
    std::mutex mutex_;
    std::size_t total_ = 0;
    std::map<std::string, std::size_t> principals_;
};
void handleRequest(Connection &connection, Repository &repository, SubscriptionAdmission &admission) {
    auto fd = connection.fd;
    std::string bytes;
    std::array<char, 8192> buffer{};
    auto receive = [&bytes, &buffer, &connection]() {
        auto n = connection.tls ? SSL_read(connection.tls.get(), buffer.data(), static_cast<int>(buffer.size()))
                                : ::recv(connection.fd, buffer.data(), buffer.size(), 0);
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
    std::string line;
    std::getline(headers, line);
    std::string req_line = line;
    if (!req_line.empty() && req_line.back() == '\r')
        req_line.pop_back();
    std::istringstream req_stream(req_line);
    std::string method, path, proto;
    req_stream >> method >> path >> proto;

    if (method == "GET" && (path == "/health" || path == "/health/")) {
        reply(connection, 200, {{"name", "axon"}, {"protocol", 1}});
        return;
    }
    if (method == "GET" && path == "/metrics") {
        auto metrics = repository.metricsPrometheus();
        auto header =
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4\r\nConnection: close\r\nContent-Length: " +
            std::to_string(metrics.size()) + "\r\n\r\n";
        sendAll(connection, header);
        sendAll(connection, metrics);
        return;
    }
    if (method == "GET" && path.starts_with("/cas/")) {
        auto sub = path.substr(5);
        auto slash = sub.rfind('/');
        auto hash = (slash == std::string::npos) ? sub : sub.substr(slash + 1);
        if (repository.store().has(hash)) {
            auto blob = repository.store().blob(hash);
            auto header = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                          "Cache-Control: public, max-age=31536000, immutable\r\n"
                          "Connection: close\r\nContent-Length: " +
                          std::to_string(blob.size()) + "\r\n\r\n";
            sendAll(connection, header);
            sendAll(connection, blob);
            return;
        }
        auto header = "HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
        sendAll(connection, header);
        return;
    }
    bool streaming = method == "POST" && path == "/v1/subscribe";
    require(method == "POST" && (path == "/rpc" || path == "/rpc/" || streaming),
            "expected POST /rpc or /v1/subscribe");
    std::size_t length = 0;
    bool seen = false;
    while (std::getline(headers, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        auto colon = line.find(':');
        require(colon != std::string::npos, "malformed HTTP header");
        auto name = line.substr(0, colon);
        for (char &c : name)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        require(name != "transfer-encoding", "chunked requests are not supported");
        if (name == "content-length") {
            require(!seen, "duplicate content length");
            seen = true;
            auto value = line.substr(colon + 1);
            auto first = value.find_first_not_of(' ');
            require(first != std::string::npos, "invalid content length");
            auto parsed = std::from_chars(value.data() + first, value.data() + value.size(), length);
            require(parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size() && length <= MAX_BODY,
                    "invalid content length");
        }
    }
    require(seen, "content length required");
    auto start = end + 4;
    while (bytes.size() - start < length)
        receive();
    auto envelope = Json::parse(bytes.substr(start, length));
    if (streaming)
        require(envelope.at("payload").value("command", "") == "subscribe", "stream requires a subscribe request");
    auto result = repository.request(envelope);
    if (!result) {
        reply(connection, 400, {{"ok", false}, {"error", result.error()}});
        return;
    }
    if (!streaming) {
        reply(connection, 200, {{"ok", true}, {"result", *result}});
        return;
    }
    SubscriptionAdmission::Lease subscription(admission, envelope.at("principal").get<std::string>());
    if (!subscription.acquired) {
        reply(connection, 429, {{"ok", false}, {"error", "subscription limit: 8 per server, 2 per principal"}});
        return;
    }
    auto options = envelope.at("payload").value("options", Json::object());
    auto args = envelope.at("payload").value("args", Json::array());
    auto partition = args.empty() ? options.value("partition", "") : args.at(0).get<std::string>();
    auto line_filter = options.value("line", "");
    std::vector<std::string> paths;
    std::istringstream patterns(options.value("paths", ""));
    std::string pattern;
    while (std::getline(patterns, pattern, ','))
        if (!pattern.empty())
            paths.push_back(pattern);
    auto cursor = std::stoull(options.value("from", "0"));
    auto principal = envelope.at("principal").get<std::string>();
    auto identity = repository.identity(principal);
    auto expires = identity.value("expires", std::int64_t{0});
    sendAll(
        connection,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n");
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
    auto heartbeat = std::chrono::steady_clock::now();
    do {
        for (auto const &event : *result) {
            cursor = event.at("offset").get<std::size_t>() + 1;
            sendAll(connection, "id: " + std::to_string(cursor - 1) + "\ndata: " + event.dump() + "\n\n");
        }
        if (std::chrono::steady_clock::now() >= heartbeat) {
            sendAll(connection, ": ping\n\n");
            heartbeat = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            auto current = repository.identity(principal);
            if (current != identity)
                break;
        }
        pollfd peer{fd, POLLIN, 0};
        if (::poll(&peer, 1, 100) > 0)
            break; // Disconnect or unexpected further request bytes.
        if (expires != 0 && expires <= axon::now())
            break;
        result = repository.eventsSince(cursor, partition, line_filter, paths);
    } while (!stopped && std::chrono::steady_clock::now() < deadline);
}
void handle(int fd, Repository &repository, SSL_CTX *context, SubscriptionAdmission &admission) {
    timeval timeout{10, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    Connection connection(fd, context);
    try {
        handleRequest(connection, repository, admission);
    } catch (std::exception const &error) {
        reply(connection, 400, {{"ok", false}, {"error", error.what()}});
    }
}
std::size_t writeResponse(char *data, std::size_t size, std::size_t count, void *context) {
    auto &output = *static_cast<std::string *>(context);
    auto bytes = size * count;
    if (output.size() + bytes > MAX_BODY)
        return 0;
    output.append(data, bytes);
    return bytes;
}

class ThreadPool {
public:
    explicit ThreadPool(std::size_t threads = 16) {
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
    ~ThreadPool() {
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
} // namespace
void serve(Repository &repository, std::string_view address, Path const &certificate, Path const &key) {
    require(certificate.empty() == key.empty(), "--tls-cert and --tls-key must be supplied together");
    std::unique_ptr<SSL_CTX, decltype(&SSL_CTX_free)> tls(nullptr, SSL_CTX_free);
    if (!certificate.empty()) {
        tls.reset(SSL_CTX_new(TLS_server_method()));
        require(bool(tls) && SSL_CTX_set_min_proto_version(tls.get(), TLS1_2_VERSION) == 1,
                "TLS initialization failed");
        require(SSL_CTX_use_certificate_chain_file(tls.get(), certificate.c_str()) == 1 &&
                    SSL_CTX_use_PrivateKey_file(tls.get(), key.c_str(), SSL_FILETYPE_PEM) == 1 &&
                    SSL_CTX_check_private_key(tls.get()) == 1,
                "invalid TLS certificate or private key");
    }
    auto colon = address.rfind(':');
    require(colon != std::string_view::npos, "listen address must be host:port");
    auto host = std::string(address.substr(0, colon));
    auto port = std::string(address.substr(colon + 1));
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
    action.sa_handler = stop;
    ::sigemptyset(&action.sa_mask);
    ::sigaction(SIGINT, &action, nullptr);
    ::sigaction(SIGTERM, &action, nullptr);
    struct sigaction ignore{};
    ignore.sa_handler = SIG_IGN;
    ::sigemptyset(&ignore.sa_mask);
    ::sigaction(SIGPIPE, &ignore, nullptr);
    std::cerr << "axon serving " << address << '\n';
    std::jthread executor([&repository](std::stop_token token) { repository.runExecutor(token); });
    SubscriptionAdmission admission;
    ThreadPool pool(16);
    while (!stopped) {
        pollfd event{listener.get(), POLLIN, 0};
        if (::poll(&event, 1, 250) <= 0)
            continue;
        auto accepted = ::accept4(listener.get(), nullptr, nullptr, SOCK_CLOEXEC);
        if (accepted < 0)
            continue;
        pool.push([accepted, &repository, &admission, context = tls.get()]() {
            Descriptor connection(accepted);
            try {
                handle(connection.get(), repository, context, admission);
            } catch (std::exception const &) {
                // Handshake failures and disconnected clients have no writable response channel.
            }
        });
    }
}
Json remoteRequest(std::string_view server, Json const &envelope) {
    initializeCurl();
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
    require(bool(curl), "curl initialization failed");
    auto url = std::string(server);
    while (url.ends_with('/'))
        url.pop_back();
    url += "/rpc";
    auto body = envelope.dump();
    std::string response;
    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_PROTOCOLS_STR, "http,https");
    if (auto ca = std::getenv("AXON_CA_BUNDLE"); ca && *ca)
        curl_easy_setopt(curl.get(), CURLOPT_CAINFO, ca);
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size()));
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, writeResponse);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, 600L);
    curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
    CURLcode result = CURLE_OK;
    for (int attempt = 0; attempt < 3; ++attempt) {
        response.clear();
        result = curl_easy_perform(curl.get());
        // Retry only failures that establish no connection: a lost response may
        // follow a committed mutation, so replaying that request is unsafe.
        if (result != CURLE_COULDNT_CONNECT && result != CURLE_COULDNT_RESOLVE_HOST)
            break;
        if (attempt < 2)
            std::this_thread::sleep_for(std::chrono::milliseconds(100 * (1 << attempt)));
    }
    require(result == CURLE_OK, curl_easy_strerror(result));
    auto parsed = Json::parse(response);
    require(parsed.value("ok", false), parsed.value("error", "invalid server response"));
    return parsed.at("result");
}
std::string cachedBlob(std::string_view server, std::string_view id) {
    Store cache(configDirectory() / "client-cache");
    if (cache.has(id))
        return cache.blob(id);
    require(id.size() == 64 && id.find_first_not_of("0123456789abcdef") == std::string_view::npos, "invalid blob ID");
    initializeCurl();
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
    require(bool(curl), "curl initialization failed");
    auto url = std::string(server);
    while (url.ends_with('/'))
        url.pop_back();
    url += "/cas/" + std::string(id);
    std::string response;
    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_PROTOCOLS_STR, "http,https");
    if (auto ca = std::getenv("AXON_CA_BUNDLE"); ca && *ca)
        curl_easy_setopt(curl.get(), CURLOPT_CAINFO, ca);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, writeResponse);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, 600L);
    curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
    auto result = curl_easy_perform(curl.get());
    require(result == CURLE_OK, curl_easy_strerror(result));
    long status = 0;
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
    require(status == 200, "blob download failed");
    require(cache.putBlob(response) == id, "blob download hash mismatch");
    return response;
}
void streamRequest(std::string_view server, Json const &envelope, std::function<void(Json const &)> const &consume) {
    initializeCurl();
    struct Stream {
        std::string pending;
        std::function<void(Json const &)> consume;
        std::exception_ptr error;
    } stream{{}, consume, {}};
    auto receive = [](char *data, std::size_t size, std::size_t count, void *context) -> std::size_t {
        auto &state = *static_cast<Stream *>(context);
        try {
            auto bytes = size * count;
            require(state.pending.size() + bytes <= MAX_BODY, "event exceeds response limit");
            state.pending.append(data, bytes);
            std::size_t end;
            while ((end = state.pending.find('\n')) != std::string::npos) {
                auto line = state.pending.substr(0, end);
                state.pending.erase(0, end + 1);
                if (line.starts_with("data: "))
                    state.consume(Json::parse(line.substr(6)));
            }
            return bytes;
        } catch (...) {
            state.error = std::current_exception();
            return 0;
        }
    };
    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), curl_easy_cleanup);
    require(bool(curl), "curl initialization failed");
    auto url = std::string(server);
    while (url.ends_with('/'))
        url.pop_back();
    url += "/v1/subscribe";
    auto body = envelope.dump();
    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_PROTOCOLS_STR, "http,https");
    if (auto ca = std::getenv("AXON_CA_BUNDLE"); ca && *ca)
        curl_easy_setopt(curl.get(), CURLOPT_CAINFO, ca);
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, body.data());
    curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(body.size()));
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, +receive);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &stream);
    curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, 45L);
    curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);
    auto result = curl_easy_perform(curl.get());
    if (stream.error)
        std::rethrow_exception(stream.error);
    require(result == CURLE_OK, curl_easy_strerror(result));
    long status = 0;
    curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &status);
    require(status == 200, "subscription rejected: " + stream.pending);
}
} // namespace axon
