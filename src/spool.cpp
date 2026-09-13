#include "spool.hpp"

#include "repository.hpp"
#include "transport.hpp"

#include <fcntl.h>
#include <stdexcept>
#include <sys/file.h>

namespace axon {
namespace {
class Spool {
public:
    explicit Spool(Json const &config)
        : path_(configDirectory() / "spool.json"),
          lock_((std::filesystem::create_directories(path_.parent_path()),
                 ::open((path_.parent_path() / "spool.lock").c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600))) {
        if (::flock(lock_.get(), LOCK_EX) != 0)
            throw std::runtime_error("cannot lock offline spool");
        data = std::filesystem::exists(path_) ? Json::parse(readFile(path_)) : Json{{"entries", Json::array()}};
        if (!data.at("entries").empty() &&
            (data.at("server") != config.at("server") || data.at("principal") != config.at("principal")))
            throw std::runtime_error("offline spool belongs to another server or principal");
        data["server"] = config.at("server");
        data["principal"] = config.at("principal");
    }
    void save() const {
        writeFile(path_, data.dump());
    }
    Json data;

private:
    Path path_;
    Descriptor lock_;
};
} // namespace
Json spoolEdit(Json request, Json const &config) {
    Spool spool(config);
    request["operation_id"] = randomHex();
    spool.data["entries"].push_back(request);
    spool.save();
    return {{"queued", request.at("operation_id")}, {"pending", spool.data.at("entries").size()}};
}
Json replayEdits(Json const &config, std::string_view seed) {
    Spool spool(config);
    std::size_t replayed = 0;
    auto &entries = spool.data["entries"];
    while (!entries.empty()) {
        auto result = remoteRequest(config.at("server").get<std::string>(),
                                    signedRequest(entries.at(0), config.at("principal").get<std::string>(), seed));
        if (result.is_object() && result.contains("error"))
            throw std::runtime_error(result.at("error").get<std::string>());
        entries.erase(entries.begin());
        spool.save();
        ++replayed;
    }
    return {{"replayed", replayed}, {"pending", 0}};
}
} // namespace axon
