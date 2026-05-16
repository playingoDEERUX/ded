#pragma once
#include <string>
#include <cstdint>
#include <fstream>
#include <chrono>
#include <random>

namespace Util {
    inline uint64_t MixTriple64(uint64_t a, uint64_t b, uint64_t c)
    {
        a = a - b;  a = a - c;  a = a ^ (c >> 13);
        b = b - c;  b = b - a;  b = b ^ (a << 8);
        c = c - a;  c = c - b;  c = c ^ (b >> 13);
        a = a - b;  a = a - c;  a = a ^ (c >> 12);
        b = b - c;  b = b - a;  b = b ^ (a << 16);
        c = c - a;  c = c - b;  c = c ^ (b >> 5);
        a = a - b;  a = a - c;  a = a ^ (c >> 3);
        b = b - c;  b = b - a;  b = b ^ (a << 10);
        c = c - a;  c = c - b;  c = c ^ (b >> 15);
        return c;
    }


    inline void AppendToFile(const std::string& filename, const std::string& text) {
        std::ofstream file(filename, std::ios::app); // open in append mode
        if (!file)
            return;

        file << text;
        file.close();
    }


    inline uint64_t GetUTCMonthSinceEpoch()
    {
        auto now = time(nullptr);
        tm gmt{};
#ifdef _WIN32
        gmtime_s(&gmt, &now);
#else
        gmtime_r(&now, &gmt);
#endif
        return uint64_t(gmt.tm_year) * 12ull + uint64_t(gmt.tm_mon);
    }

    inline uint64_t SplitMix64(uint64_t& x)
    {
        x += 0x9E3779B97F4A7C15ULL;
        uint64_t z = x;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }

    inline uint64_t GetCurrentUTCMs() {
        using namespace std::chrono;
        auto now = system_clock::now();                           // current time in system_clock
        auto epoch = now.time_since_epoch();                      // duration since Unix epoch
        return duration_cast<milliseconds>(epoch).count();       // convert to milliseconds
    }

    inline uint64_t GetCurrentUTCSec() {
        using namespace std::chrono;
        auto now = system_clock::now();                           // current time in system_clock
        auto epoch = now.time_since_epoch();                      // duration since Unix epoch
        return duration_cast<seconds>(epoch).count();       // convert to milliseconds
    }

    inline uint32_t GetSecure32() {
        std::random_device rd;
        return rd();
    }

    inline uint64_t GetSecure64() {
        std::random_device rd;
        uint64_t high = static_cast<uint64_t>(rd()) << 32;
        uint64_t low = static_cast<uint64_t>(rd());
        return high | low;
    }


    inline std::mt19937& GetRNG() {
        static thread_local std::random_device rd;
        static thread_local std::mt19937 rng(rd());  // Initialized once, on first call
        return rng;
    }

    inline uint32_t DiceRoll() {
        static std::uniform_int_distribution<uint32_t> dist(0, UINT_MAX);
        return dist(Util::GetRNG());
    }

}