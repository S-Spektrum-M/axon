#pragma once

#include "repository.hpp"

#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

namespace axon {

struct BenchConfig {
    std::string dir;
    int agents = 64;
    int domains = 8;
    int files = 16;
    int duration_secs = 5;
    int reads = 2;
    double hot_fraction = 0.0;
    double cross_fraction = 0.0;
    bool sync = false;
};

struct BenchResult {
    std::int64_t landings = 0;
    std::int64_t fast = 0;
    std::int64_t rebase = 0;
    std::int64_t merge = 0;
    std::int64_t conflicts = 0;
    std::int64_t other = 0;
    std::int64_t cross_domain = 0;
    double elapsed_secs = 0.0;
    std::int64_t p50_us = 0;
    std::int64_t p90_us = 0;
    std::int64_t p99_us = 0;
    std::int64_t max_us = 0;
    std::unordered_map<std::string, int> per_domain;
    double busiest_domain_rate = 0.0;

    void print(std::ostream &os) const;
};

BenchResult runBench(BenchConfig const &config, std::ostream &progress = std::cerr);

} // namespace axon
