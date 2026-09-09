#pragma once
#include "storage.hpp"

#include <string>
#include <string_view>

namespace axon {
struct CacheConfig {
    std::string listen = "127.0.0.1:7071";
    std::string upstream = "http://127.0.0.1:7070";
    Path dir;
};

void serveCache(CacheConfig const &config);
} // namespace axon
