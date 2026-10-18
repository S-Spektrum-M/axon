#include "web.hpp"

#include "repository.hpp"
#include "transport.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <array>
#include <cctype>
#include <charconv>
#include <iostream>
#include <map>
#include <memory>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace axon {
namespace {
constexpr std::size_t MAX_BODY = 64 * 1024;
constexpr std::size_t MAX_HEADER = 16 * 1024;
constexpr std::size_t MAX_TEXT = 1024 * 1024;
extern char const PAGE[];
void require(bool condition, std::string_view message) {
    if (!condition)
        throw std::runtime_error(std::string(message));
}
struct HttpRequest {
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::string body;
};
HttpRequest readRequest(int fd) {
    std::string bytes;
    std::array<char, 8192> buffer{};
    auto receive = [&]() {
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
    HttpRequest request;
    std::istringstream headers(bytes.substr(0, end));
    std::string line;
    std::getline(headers, line);
    std::istringstream(line) >> request.method >> request.path;
    while (std::getline(headers, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        auto colon = line.find(':');
        require(colon != std::string::npos, "malformed HTTP header");
        auto name = line.substr(0, colon);
        for (char &c : name)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        auto value = line.substr(colon + 1);
        value.erase(0, value.find_first_not_of(' '));
        require(name != "transfer-encoding", "chunked requests are not supported");
        require(request.headers.emplace(name, value).second, "duplicate HTTP header");
    }
    std::size_t length = 0;
    if (auto found = request.headers.find("content-length"); found != request.headers.end()) {
        auto const &value = found->second;
        auto parsed = std::from_chars(value.data(), value.data() + value.size(), length);
        require(parsed.ec == std::errc{} && parsed.ptr == value.data() + value.size() && length <= MAX_BODY,
                "invalid content length");
    }
    auto start = end + 4;
    while (bytes.size() - start < length)
        receive();
    request.body = bytes.substr(start, length);
    return request;
}
void respond(int fd, int status, std::string_view type, std::string_view body) {
    auto header = "HTTP/1.1 " + std::to_string(status) + (status == 200 ? " OK" : " Error") +
                  "\r\nContent-Type: " + std::string(type) +
                  "\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer"
                  "\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src "
                  "'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
                  "\r\nConnection: close\r\nContent-Length: " +
                  std::to_string(body.size()) + "\r\n\r\n";
    auto data = header + std::string(body);
    std::string_view rest = data;
    while (!rest.empty()) {
        auto n = ::send(fd, rest.data(), rest.size(), MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR)
            continue;
        require(n > 0, "socket write failed");
        rest.remove_prefix(static_cast<std::size_t>(n));
    }
}
void respondJson(int fd, int status, Json const &value) {
    // File contents need not be UTF-8; replacement keeps the response well-formed.
    respond(fd, status, "application/json", value.dump(-1, ' ', false, Json::error_handler_t::replace));
}
Json fileView(std::string const &bytes) {
    Json result{{"kind", "file"}, {"size", bytes.size()}};
    if (bytes.find('\0') != std::string::npos)
        result["binary"] = true;
    else {
        result["text"] = bytes.substr(0, MAX_TEXT);
        result["truncated"] = bytes.size() > MAX_TEXT;
    }
    return result;
}
void handle(int fd,
            std::string const &token,
            std::vector<std::string> const &hosts,
            std::function<Json(Json)> const &rpc) {
    timeval timeout{10, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    try {
        auto request = readRequest(fd);
        // A Host check defeats DNS rebinding; the token and custom header defeat other local pages.
        auto host = request.headers.find("host");
        if (host == request.headers.end() || std::find(hosts.begin(), hosts.end(), host->second) == hosts.end()) {
            respondJson(fd, 403, {{"error", "unexpected Host header"}});
            return;
        }
        if (request.method == "GET" && (request.path == "/" || request.path == "/index.html")) {
            respond(fd, 200, "text/html; charset=utf-8", PAGE);
            return;
        }
        if (request.method != "POST" || request.path != "/api") {
            respondJson(fd, 404, {{"error", "not found"}});
            return;
        }
        auto supplied = request.headers.find("x-axon-token");
        if (supplied == request.headers.end() || supplied->second != token) {
            respondJson(fd, 403, {{"error", "missing or invalid token; open the URL printed by axon web"}});
            return;
        }
        respondJson(fd, 200, webRequest(Json::parse(request.body), rpc));
    } catch (std::exception const &error) {
        try {
            respondJson(fd, 400, {{"error", error.what()}});
        } catch (std::exception const &) {
            // The client disconnected; there is no response channel.
        }
    }
}
} // namespace
Json webRequest(Json const &call, std::function<Json(Json)> const &rpc) {
    static Json const ALLOWED{{"whoami", Json::array()},
                              {"lines", Json::array()},
                              {"log", {"line", "path", "limit"}},
                              {"get", Json::array()},
                              {"status", {"all", "status"}},
                              {"queue", {"line"}},
                              {"diff", Json::array()}};
    require(call.is_object(), "expected a JSON object");
    auto command = call.value("command", "");
    require(ALLOWED.contains(command), "command is not available in the web view: " + command);
    auto args = call.value("args", Json::array());
    require(args.is_array() && args.size() <= 2, "invalid arguments");
    for (auto const &arg : args)
        require(arg.is_string(), "arguments must be strings");
    Json options = Json::object();
    for (auto const &[name, value] : call.value("options", Json::object()).items()) {
        auto const &allowed = ALLOWED.at(command);
        require(std::find(allowed.begin(), allowed.end(), Json(name)) != allowed.end(),
                "unsupported option for " + command + ": " + name);
        require(value.is_string(), "option values must be strings");
        options[name] = value;
    }
    auto result = rpc({{"command", command}, {"args", args}, {"options", options}});
    if (result.is_object() && result.contains("error") && result.at("error").is_string())
        throw std::runtime_error(result.at("error").get<std::string>());
    bool bytes = result.is_object() && result.contains("bytes") && result.at("bytes").is_string();
    if (command == "get")
        return bytes ? fileView(unhex(result.at("bytes").get<std::string>()))
                     : Json{{"kind", "dir"}, {"entries", result}};
    if (command == "diff" && bytes)
        return fileView(unhex(result.at("bytes").get<std::string>()));
    return result;
}
void serveWeb(Json const &config, std::string_view seed, std::string_view address) {
    auto colon = address.rfind(':');
    require(colon != std::string_view::npos, "listen address must be host:port");
    auto host = std::string(address.substr(0, colon));
    auto port = std::string(address.substr(colon + 1));
    // The proxy signs as the configured identity, so it must not be reachable off-host.
    require(host == "127.0.0.1" || host == "localhost", "the web view listens only on 127.0.0.1 or localhost");
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *raw = nullptr;
    require(::getaddrinfo("127.0.0.1", port.c_str(), &hints, &raw) == 0, "invalid listen address");
    std::unique_ptr<addrinfo, decltype(&freeaddrinfo)> info(raw, freeaddrinfo);
    Descriptor listener(::socket(info->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0));
    int enabled = 1;
    ::setsockopt(listener.get(), SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    require(::bind(listener.get(), info->ai_addr, info->ai_addrlen) == 0, "bind failed");
    require(::listen(listener.get(), 64) == 0, "listen failed");
    sockaddr_in bound{};
    socklen_t size = sizeof(bound);
    require(::getsockname(listener.get(), reinterpret_cast<sockaddr *>(&bound), &size) == 0, "getsockname failed");
    port = std::to_string(ntohs(bound.sin_port));
    std::vector<std::string> const hosts{"127.0.0.1:" + port, "localhost:" + port};
    auto const token = randomHex(16);
    auto const server = config.at("server").get<std::string>();
    auto const principal = config.at("principal").get<std::string>();
    auto const key = std::string(seed);
    std::function<Json(Json)> const rpc = [&](Json payload) {
        return remoteRequest(server, signedRequest(payload, principal, key));
    };
    struct sigaction ignore{};
    ignore.sa_handler = SIG_IGN;
    ::sigemptyset(&ignore.sa_mask);
    ::sigaction(SIGPIPE, &ignore, nullptr);
    std::cout << "http://127.0.0.1:" << port << "/#token=" << token << std::endl;
    std::cerr << "axon web view for " << principal << " on " << server << "; Ctrl-C stops it\n";
    while (true) {
        auto accepted = ::accept4(listener.get(), nullptr, nullptr, SOCK_CLOEXEC);
        if (accepted < 0)
            continue;
        // The listener lives until the process exits, so these references outlive every worker.
        std::thread([accepted, &token, &hosts, &rpc]() {
            Descriptor connection(accepted);
            handle(connection.get(), token, hosts, rpc);
        }).detach();
    }
}
namespace {
char const PAGE[] = R"html(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Axon</title>
<style>
:root {
  --bg: #f7f7f5; --panel: #ffffff; --text: #1d1d1b; --muted: #6b6b66; --border: #e3e3de;
  --accent: #3b5bdb; --accent-soft: #e8edfd; --add: #e6f4ea; --add-text: #1e6b34;
  --del: #fdecea; --del-text: #a12622; --hunk: #eef1f8; --code: #fbfbfa;
  --ok: #2b8a3e; --warn: #c27c0e; --bad: #c92a2a; --idle: #868e96;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #161616; --panel: #1f1f1f; --text: #e8e8e6; --muted: #9a9a94; --border: #333331;
    --accent: #8ea4ff; --accent-soft: #252c47; --add: #17321f; --add-text: #8fd6a2;
    --del: #3a1b1b; --del-text: #ffaaa5; --hunk: #23283a; --code: #1a1a1a;
    --ok: #69db7c; --warn: #ffc94d; --bad: #ff8787; --idle: #adb5bd;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
code, pre, .mono { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 13px; }
header { display: flex; align-items: center; gap: 24px; padding: 0 24px; height: 52px;
  border-bottom: 1px solid var(--border); background: var(--panel); position: sticky; top: 0; z-index: 1; }
header .brand { font-weight: 650; letter-spacing: .02em; }
nav { display: flex; gap: 4px; }
nav a { padding: 6px 12px; border-radius: 6px; color: var(--muted); }
nav a.active { background: var(--accent-soft); color: var(--accent); }
nav a:hover { text-decoration: none; color: var(--text); }
header .who { margin-left: auto; color: var(--muted); font-size: 13px; }
main { max-width: 1100px; margin: 0 auto; padding: 24px; }
h1 { font-size: 20px; margin: 0 0 4px; font-weight: 600; }
.sub { color: var(--muted); margin-bottom: 20px; }
.toolbar { display: flex; align-items: center; gap: 12px; margin-bottom: 16px; flex-wrap: wrap; }
select { font: inherit; padding: 4px 8px; border: 1px solid var(--border); border-radius: 6px;
  background: var(--panel); color: var(--text); }
.crumbs { font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 13px; }
.crumbs span.sep { color: var(--muted); margin: 0 4px; }
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }
.panel + .panel { margin-top: 16px; }
.panel > .title { padding: 10px 16px; border-bottom: 1px solid var(--border); font-weight: 600;
  display: flex; justify-content: space-between; align-items: center; gap: 12px; }
.panel > .title .meta { font-weight: 400; color: var(--muted); font-size: 13px; }
table { width: 100%; border-collapse: collapse; }
td, th { text-align: left; padding: 8px 16px; border-bottom: 1px solid var(--border); vertical-align: top; }
th { font-weight: 500; color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .04em; }
tr:last-child td { border-bottom: 0; }
tr.row:hover td { background: var(--accent-soft); cursor: pointer; }
td.num { width: 1%; white-space: nowrap; color: var(--muted); font-variant-numeric: tabular-nums; }
td.time { width: 1%; white-space: nowrap; color: var(--muted); }
.icon { display: inline-block; width: 18px; color: var(--muted); }
.code { overflow-x: auto; background: var(--code); font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
  font-size: 13px; line-height: 1.6; }
.code table td { border: 0; padding: 0 12px; white-space: pre; }
.code td.ln { width: 1%; text-align: right; color: var(--muted); user-select: none; padding-left: 16px; }
.code tr.add td { background: var(--add); color: var(--add-text); }
.code tr.del td { background: var(--del); color: var(--del-text); }
.code tr.hunk td { background: var(--hunk); color: var(--muted); }
.code tr.file td { background: var(--panel); font-weight: 600; padding-top: 8px; padding-bottom: 8px;
  border-top: 1px solid var(--border); }
.badge { display: inline-block; padding: 1px 8px; border-radius: 999px; font-size: 12px; font-weight: 500;
  border: 1px solid currentColor; white-space: nowrap; }
.s-landed { color: var(--ok); } .s-blocked, .s-submitted, .s-queued, .s-waiting { color: var(--warn); }
.s-conflicted, .s-rejected, .s-failed { color: var(--bad); } .s-abandoned, .s-superseded { color: var(--idle); }
.tag { display: inline-block; padding: 0 6px; border-radius: 4px; background: var(--accent-soft);
  color: var(--accent); font-size: 12px; margin-right: 4px; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 6px 20px; margin: 0; padding: 14px 16px; }
dt { color: var(--muted); } dd { margin: 0; overflow-wrap: anywhere; }
.paths { color: var(--muted); font-size: 13px; }
.empty, .error, .loading { padding: 24px 16px; color: var(--muted); }
.error { color: var(--bad); white-space: pre-wrap; }
.filters { display: flex; gap: 4px; flex-wrap: wrap; }
.filters a { padding: 3px 10px; border-radius: 999px; border: 1px solid var(--border); color: var(--muted); font-size: 13px; }
.filters a.active { border-color: var(--accent); color: var(--accent); }
@media (max-width: 640px) {
  header { gap: 12px; padding: 0 16px; } header .who { display: none; }
  main { padding: 16px; } td, th { padding: 8px 10px; } .hide-sm { display: none; }
}
</style>
</head>
<body>
<header>
  <span class="brand">Axon</span>
  <nav>
    <a href="#/files" data-tab="files">Files</a>
    <a href="#/history" data-tab="history">History</a>
    <a href="#/stacks" data-tab="stacks">Stacks</a>
    <a href="#/queue" data-tab="queue">Queue</a>
  </nav>
  <span class="who" id="who"></span>
</header>
<main id="main"></main>
<script>
"use strict";
(() => {
  // The token arrives in the fragment so it never reaches server logs or Referer headers.
  const match = location.hash.match(/token=([0-9a-f]+)/);
  let token = "";
  try {
    if (match) sessionStorage.setItem("axon-token", match[1]);
    token = (match && match[1]) || sessionStorage.getItem("axon-token") || "";
  } catch (_) { token = match ? match[1] : ""; }
  if (match) history.replaceState(null, "", location.pathname + (location.hash.replace(/[#&]?token=[0-9a-f]+/, "") || "#/files"));

  const main = document.getElementById("main");
  const h = (tag, attrs, ...children) => {
    const node = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === undefined || v === null || v === false) continue;
      if (k === "onclick") node.addEventListener("click", v); else node.setAttribute(k, v);
    }
    for (const child of children.flat()) if (child !== null && child !== undefined && child !== false)
      node.append(child instanceof Node ? child : String(child));
    return node;
  };
  const api = async (command, args = [], options = {}) => {
    const response = await fetch("/api", { method: "POST",
      headers: { "Content-Type": "application/json", "X-Axon-Token": token },
      body: JSON.stringify({ command, args, options }) });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || response.statusText);
    return body;
  };
  const enc = (s) => s.split("/").map(encodeURIComponent).join("/");
  const short = (id) => (id || "").slice(0, 10);
  const ago = (t) => {
    if (!t) return "";
    const s = Math.max(0, Date.now() / 1000 - t);
    if (s < 60) return "just now";
    if (s < 3600) return Math.floor(s / 60) + "m ago";
    if (s < 86400) return Math.floor(s / 3600) + "h ago";
    if (s < 86400 * 30) return Math.floor(s / 86400) + "d ago";
    return new Date(t * 1000).toLocaleDateString();
  };
  const when = (t) => h("span", { title: t ? new Date(t * 1000).toLocaleString() : "" }, ago(t));
  const badge = (status) => h("span", { class: "badge s-" + status }, status);
  const go = (href) => () => { location.hash = href; };
  const show = (...nodes) => { main.replaceChildren(...nodes); };
  const failure = (error) => h("div", { class: "panel" }, h("div", { class: "error" }, error.message || String(error)));
  const size = (n) => n < 1024 ? n + " B" : n < 1048576 ? (n / 1024).toFixed(1) + " KB" : (n / 1048576).toFixed(1) + " MB";

  let lines = null;
  const loadLines = async () => (lines = lines || await api("lines"));
  const lineSelect = async (current, onchange) => {
    const all = await loadLines();
    const select = h("select", {}, Object.keys(all).sort().map((name) =>
      h("option", { value: name, selected: name === current }, name)));
    select.addEventListener("change", () => onchange(select.value));
    return select;
  };

  const codeView = (text) => {
    const rows = text.replace(/\n$/, "").split("\n").map((line, i) =>
      h("tr", {}, h("td", { class: "ln" }, i + 1), h("td", {}, line)));
    return h("div", { class: "code" }, h("table", {}, rows));
  };
  const diffView = (text) => {
    if (!text.trim()) return h("div", { class: "empty" }, "No textual changes.");
    let oldN = 0, newN = 0;
    const rows = [];
    for (const line of text.replace(/\n$/, "").split("\n")) {
      const hunk = line.match(/^@@ -(\d+)(?:,\d+)? \+(\d+)/);
      if (hunk) { oldN = +hunk[1]; newN = +hunk[2]; rows.push(h("tr", { class: "hunk" }, h("td", { class: "ln" }), h("td", { class: "ln" }), h("td", {}, line))); }
      else if (/^diff /.test(line))
        rows.push(h("tr", { class: "file" }, h("td", { colspan: 3 }, line.replace(/^diff \S+ a\/(.*) b\/.*$/, "$1"))));
      else if (/^(--- |\+\+\+ |index )/.test(line)) continue;
      else if (/^(new file|deleted file|Binary)/.test(line))
        rows.push(h("tr", { class: "hunk" }, h("td", { class: "ln" }), h("td", { class: "ln" }), h("td", {}, line)));
      else if (line.startsWith("+")) rows.push(h("tr", { class: "add" }, h("td", { class: "ln" }), h("td", { class: "ln" }, newN++), h("td", {}, line)));
      else if (line.startsWith("-")) rows.push(h("tr", { class: "del" }, h("td", { class: "ln" }, oldN++), h("td", { class: "ln" }), h("td", {}, line)));
      else rows.push(h("tr", {}, h("td", { class: "ln" }, oldN++), h("td", { class: "ln" }, newN++), h("td", {}, line)));
    }
    return h("div", { class: "code" }, h("table", {}, rows));
  };

  // #/files/<line>@<n>/<path>
  async function files(rest) {
    const [at, ...parts] = rest ? rest.split("/") : [];
    const path = parts.map(decodeURIComponent).filter(Boolean).join("/");
    const all = await loadLines();
    let [line, n] = (at ? decodeURIComponent(at) : "trunk").split("@");
    if (!all[line]) line = Object.keys(all)[0];
    const head = all[line].length - 1;
    const pinned = n !== undefined && n !== "";
    n = pinned ? +n : head;
    const position = line + "@" + n;
    const href = (p) => "#/files/" + encodeURIComponent(pinned ? position : line) + (p ? "/" + enc(p) : "");
    const crumbs = h("span", { class: "crumbs" }, h("a", { href: href("") }, line));
    let acc = "";
    for (const part of path ? path.split("/") : []) {
      acc = acc ? acc + "/" + part : part;
      crumbs.append(h("span", { class: "sep" }, "/"), h("a", { href: href(acc) }, part));
    }
    const snapshot = h("select", {}, all[line].slice().reverse().map((entry) =>
      h("option", { value: entry.n, selected: entry.n === n, disabled: entry.pruned },
        "@" + entry.n + (entry.n === head ? " (head)" : "") + (entry.title ? " — " + entry.title : ""))));
    snapshot.addEventListener("change", () => {
      const v = +snapshot.value;
      location.hash = "#/files/" + encodeURIComponent(v === head ? line : line + "@" + v) + (path ? "/" + enc(path) : "");
    });
    const toolbar = h("div", { class: "toolbar" },
      await lineSelect(line, (l) => { location.hash = "#/files/" + encodeURIComponent(l); }), snapshot, crumbs);
    show(h("h1", {}, "Files"), h("div", { class: "sub" }, "Browsing ", h("code", {}, position), " (read-only)"), toolbar,
      h("div", { class: "panel" }, h("div", { class: "loading" }, "Loading…")));
    const result = await api("get", [position, path]);
    let body;
    if (result.kind === "dir") {
      const names = Object.keys(result.entries).sort((a, b) =>
        (result.entries[a].kind === "dir" ? 0 : 1) - (result.entries[b].kind === "dir" ? 0 : 1) || a.localeCompare(b));
      const rows = names.map((name) => {
        const e = result.entries[name], p = path ? path + "/" + name : name;
        const icon = e.kind === "dir" ? "▸" : e.kind === "link" ? "↪" : "·";
        return h("tr", { class: "row", onclick: go(href(p)) },
          h("td", {}, h("span", { class: "icon" }, icon), h("a", { href: href(p) }, name + (e.kind === "dir" ? "/" : ""))),
          h("td", { class: "num" }, e.exec ? "exec" : ""),
          h("td", { class: "num" }, e.size !== undefined ? size(e.size) : ""));
      });
      body = h("div", { class: "panel" },
        h("div", { class: "title" }, path || "/", h("span", { class: "meta" }, names.length + " entries")),
        rows.length ? h("table", {}, rows) : h("div", { class: "empty" }, "Empty directory."));
    } else {
      const content = result.binary ? h("div", { class: "empty" }, "Binary file, " + size(result.size) + ".")
        : codeView(result.text);
      body = h("div", { class: "panel" },
        h("div", { class: "title" }, path, h("span", { class: "meta" }, size(result.size),
          result.truncated ? " (showing first 1 MB)" : "", " · ",
          h("a", { href: "#/history/" + encodeURIComponent(line) + "/" + enc(path) }, "history"))),
        content);
    }
    main.lastChild.replaceWith(body);
  }

  const historyTable = (entries, line) => {
    const rows = entries.slice().reverse().map((e) => {
      const target = "#/files/" + encodeURIComponent(line + "@" + e.n);
      return h("tr", { class: "row", onclick: go(e.stack ? "#/stack/" + e.stack : target) },
        h("td", { class: "num mono" }, "@" + e.n),
        h("td", {},
          h("div", {}, e.title || (e.n === 0 ? "Line created" : e.imported ? "Imported" : "(untitled)"), " ",
            e.intent ? h("span", { class: "tag" }, e.intent) : null),
          e.paths && e.paths.length ? h("div", { class: "paths mono" },
            e.paths.slice(0, 4).join("  "), e.paths.length > 4 ? "  +" + (e.paths.length - 4) + " more" : "") : null),
        h("td", { class: "hide-sm" }, e.principal || ""),
        h("td", { class: "time" }, when(e.created)),
        h("td", { class: "num hide-sm" }, h("a", { href: target, onclick: (ev) => ev.stopPropagation() }, "browse")));
    });
    return rows.length ? h("table", {}, rows) : h("div", { class: "empty" }, "No history.");
  };

  // #/history/<line>/<path>
  async function historyView(rest) {
    const [l, ...parts] = rest ? rest.split("/") : [];
    const line = l ? decodeURIComponent(l) : "trunk";
    const path = parts.map(decodeURIComponent).join("/");
    const toolbar = h("div", { class: "toolbar" },
      await lineSelect(line, (v) => { location.hash = "#/history/" + encodeURIComponent(v); }),
      path ? h("span", { class: "crumbs" }, "touching ", h("code", {}, path), " · ",
        h("a", { href: "#/history/" + encodeURIComponent(line) }, "clear")) : null);
    show(h("h1", {}, "History"), h("div", { class: "sub" }, "Landed snapshots on ", h("code", {}, line), ", newest first"),
      toolbar, h("div", { class: "panel" }, h("div", { class: "loading" }, "Loading…")));
    const options = { line, limit: "500" };
    if (path) options.path = path;
    const entries = await api("log", [], options);
    main.lastChild.replaceWith(h("div", { class: "panel" }, historyTable(entries, line)));
  }

  const STATUSES = ["all", "submitted", "blocked", "conflicted", "landed", "abandoned"];
  // #/stacks/<status>
  async function stacks(rest) {
    const filter = rest && STATUSES.includes(rest) ? rest : "all";
    const filters = h("div", { class: "filters" }, STATUSES.map((s) =>
      h("a", { href: "#/stacks/" + s, class: s === filter ? "active" : null }, s)));
    show(h("h1", {}, "Stacks"), h("div", { class: "sub" }, "Submitted changes from every principal"),
      h("div", { class: "toolbar" }, filters), h("div", { class: "panel" }, h("div", { class: "loading" }, "Loading…")));
    const options = { all: "true" };
    if (filter !== "all") options.status = filter;
    const list = (await api("status", [], options)).sort((a, b) => (b.created || 0) - (a.created || 0));
    const rows = list.map((s) => h("tr", { class: "row", onclick: go("#/stack/" + s.id) },
      h("td", { class: "num mono hide-sm" }, short(s.id)),
      h("td", {}, h("div", {}, s.title || "(untitled)", " ", s.intent ? h("span", { class: "tag" }, s.intent) : null),
        s.reason ? h("div", { class: "paths" }, s.reason) : null),
      h("td", { class: "hide-sm" }, s.principal),
      h("td", { class: "num hide-sm" }, s.line),
      h("td", { class: "num" }, badge(s.status)),
      h("td", { class: "time" }, when(s.created))));
    main.lastChild.replaceWith(h("div", { class: "panel" },
      rows.length ? h("table", {}, rows) : h("div", { class: "empty" }, "No stacks.")));
  }

  // #/stack/<id>
  async function stack(id) {
    show(h("div", { class: "loading" }, "Loading…"));
    const [s, diff] = await Promise.all([api("status", [id]), api("diff", [id]).catch((e) => ({ error: e.message }))]);
    const facts = [
      ["Status", h("span", {}, badge(s.status), s.reason ? "  " + s.reason : "")],
      ["Line", h("span", {}, s.line, s.base ? h("span", { class: "paths" }, "  based on ",
        h("a", { href: "#/files/" + encodeURIComponent(s.base.line + "@" + s.base.n) }, "@" + s.base.n)) : null)],
      s.landed ? ["Landed", h("a", { href: "#/files/" + encodeURIComponent(s.landed.line + "@" + s.landed.n) },
        s.landed.line + "@" + s.landed.n)] : null,
      ["Principal", s.principal],
      ["Created", h("span", {}, when(s.created), "  ", h("span", { class: "paths" }, new Date(s.created * 1000).toLocaleString()))],
      s.intent ? ["Intent", h("span", {}, h("span", { class: "tag" }, s.intent), s.intent_note || "")] : null,
      s.labels && s.labels.length ? ["Labels", s.labels.map((l) => h("span", { class: "tag" }, l))] : null,
      s.policy_class ? ["Policy class", s.policy_class] : null,
      s.route ? ["Route", s.route] : null,
      ["Stack ID", h("code", {}, s.id)],
    ].filter(Boolean);
    const panels = [h("div", { class: "panel" }, h("dl", {}, facts.flatMap(([k, v]) => [h("dt", {}, k), h("dd", {}, v)])))];
    if (s.requirements && s.requirements.length)
      panels.push(h("div", { class: "panel" }, h("div", { class: "title" }, "Requirements"),
        h("table", {}, h("tr", {}, h("th", {}, "Kind"), h("th", {}, "Target"), h("th", {}, "Status")),
          s.requirements.map((r) => h("tr", {}, h("td", {}, r.kind || ""), h("td", { class: "mono" }, r.target || r.group || short(r.input_hash)),
            h("td", {}, badge(r.status || "")))))));
    if (s.conflicts && s.conflicts.length)
      panels.push(h("div", { class: "panel" }, h("div", { class: "title" }, "Conflicts"),
        h("table", {}, s.conflicts.map((c) => h("tr", {}, h("td", { class: "mono" }, c.path || JSON.stringify(c)))))));
    panels.push(h("div", { class: "panel" }, h("div", { class: "title" }, "Diff",
      h("span", { class: "meta" }, (s.write_set || []).length + " paths")),
      diff.error ? h("div", { class: "error" }, diff.error) : diffView(diff.text || "")));
    show(h("div", { class: "sub" }, h("a", { href: "#/stacks" }, "← Stacks")),
      h("h1", {}, s.title || "(untitled)"), h("div", { class: "sub" }, short(s.id)), ...panels);
  }

  // #/queue/<line>
  async function queue(rest) {
    const line = rest ? decodeURIComponent(rest) : "trunk";
    const toolbar = h("div", { class: "toolbar" },
      await lineSelect(line, (v) => { location.hash = "#/queue/" + encodeURIComponent(v); }));
    show(h("h1", {}, "Merge queue"), h("div", { class: "sub" }, "Stacks waiting to land on ", h("code", {}, line)),
      toolbar, h("div", { class: "panel" }, h("div", { class: "loading" }, "Loading…")));
    const all = await api("status", [], { all: "true" });
    const waiting = all.filter((s) => s.line === line && s.queued && (s.status === "submitted" || s.status === "blocked"))
      .sort((a, b) => (a.created || 0) - (b.created || 0));
    const rows = waiting.map((s, i) => h("tr", { class: "row", onclick: go("#/stack/" + s.id) },
      h("td", { class: "num" }, i + 1),
      h("td", {}, h("div", {}, s.title || "(untitled)"), s.reason ? h("div", { class: "paths" }, s.reason) : null),
      h("td", { class: "hide-sm" }, s.principal),
      h("td", { class: "num" }, badge(s.status)),
      h("td", { class: "time" }, when(s.created))));
    main.lastChild.replaceWith(h("div", { class: "panel" },
      rows.length ? h("table", {}, rows) : h("div", { class: "empty" }, "The queue is empty.")));
  }

  const routes = { files, history: historyView, stacks, stack, queue };
  async function route() {
    const raw = location.hash.replace(/^#\/?/, "");
    const slash = raw.indexOf("/");
    let name = slash < 0 ? raw : raw.slice(0, slash);
    const rest = slash < 0 ? "" : raw.slice(slash + 1);
    if (!routes[name]) name = "files";
    for (const a of document.querySelectorAll("nav a"))
      a.classList.toggle("active", a.dataset.tab === name || (name === "stack" && a.dataset.tab === "stacks"));
    try { await routes[name](rest); window.scrollTo(0, 0); } catch (error) { show(failure(error)); }
  }
  window.addEventListener("hashchange", route);
  if (!token) { show(failure(new Error("Missing access token. Open the URL printed by `axon web`."))); return; }
  api("whoami").then((w) => { document.getElementById("who").textContent = w.principal; }).catch(() => {});
  route();
})();
</script>
</body>
</html>
)html";
} // namespace
} // namespace axon
