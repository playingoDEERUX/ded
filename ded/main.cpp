// NOTE: This is a not fully complete version, but it gets the idea/principle across very well. No liability/guarantees for this open source project!

#include <iostream>
#include <sys/stat.h>
#include <filesystem>
#include <regex>
#include <enet/enet.h> // to get access to enet_socket_* functions which implements socket operations for unix/win, simple cross-platfrom wrapper
#include <thread>
#include <chrono>
#include <cstring>
#ifdef _MSC_VER
#include <vadefs.h>
#else
#include <stdarg.h>
#endif
#include <unordered_set>
#include <climits>
#include <atomic>
#include <cstdint>
#include <immintrin.h>
#include <windows.h>
#include <print>
#include <format>
#include "SHA256d.hpp"
#include "ded_config.h"
#include "IPAddress.h"
#include "Util.h"
#define SODIUM_STATIC
#include <sodium.h>

constexpr size_t ED25519_SIG_BYTES = crypto_sign_BYTES;
constexpr size_t ED25519_PK_BYTES = crypto_sign_PUBLICKEYBYTES;

#if defined(_MSC_VER)
#include <intrin.h>

#define CURL_STATICLIB

inline bool cpu_supports_sha() {
    int regs[4];
    __cpuidex(regs, 7, 0);
    return (regs[1] & (1 << 29)) != 0; // ebx bit 29 = SHA
}

inline bool cpu_supports_avx2_raw() {
    int regs[4];
    __cpuidex(regs, 7, 0);
    return (regs[1] & (1 << 5)) != 0; // ebx bit 5 = AVX2
}

inline bool os_supports_avx() {
    int regs[4];
    __cpuid(regs, 1);

    bool osxsave = (regs[2] & (1 << 27)) != 0;
    bool avx = (regs[2] & (1 << 28)) != 0;

    if (osxsave && avx) {
        unsigned long long xcr = _xgetbv(0);
        return (xcr & 0x6) == 0x6;
    }
    return false;
}

inline bool cpu_supports_avx2() {
    return cpu_supports_avx2_raw() && os_supports_avx();
}

constexpr unsigned char TRUSTED_PUBLIC_KEY[crypto_sign_PUBLICKEYBYTES] = {
    // 32 bytes here
    // example (replace with your real key):
    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
    0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80
};

#else
// GCC / Clang

inline bool cpu_supports_sha() {
    return __builtin_cpu_supports("sha");
}

inline bool cpu_supports_avx2() {
    return __builtin_cpu_supports("avx2");
}

#endif

bool verify_ed25519_signature(
    const unsigned char* message,
    size_t message_len,
    const unsigned char signature[crypto_sign_BYTES],
    const unsigned char public_key[crypto_sign_PUBLICKEYBYTES]
)
{
    return crypto_sign_verify_detached(
        signature,
        message,
        message_len,
        public_key
    ) == 0;
}

#define POPEN _popen
#define PCLOSE _pclose

#pragma warning (disable : 4996)

static_assert(sizeof(POW_Input) == 32, "POW_Input layout mismatch");

constexpr uint16_t DISCOVERY_PORT = 23144; // change this as you like.
constexpr size_t   SCAN_RATE_PER_SEC = 20; // VERY important: keep this low enough per second to support CGNAT connections. this is VERY slow, but speeding up should come from placing multiple PoPs in a /8 and abusing math/statistics like that.
constexpr uint64_t CACHE_FLUSH_INTERVAL = 30; // seconds
constexpr uint64_t DGA_SEED = 0xC0FFEE69420BBDEFULL; // you can (should!) pick any seed for this here. ideally might be overriden later by a server that passes PoA
constexpr size_t   DGA_DOMAIN_COUNT = 1000; // monthly domain dga + IP/8 octet scan fallback hybrid. you can also send dga seed updates from authorized endpoints if needed, although you'd have to handle this yourself.
constexpr int      POW_DIFFICULTY_BITS = 34;

// the packet simultaneously is also the challenge to sign and verify.
struct DiscoveryPacket
{
    POW_Input pow;
    SHA256d_Hash hash;
};

struct DiscoveryResponse
{
    uint8_t signature[crypto_sign_BYTES];
};

std::string generate_dga_domain(uint64_t idx)
{
    static const char* COMMON_TLDS[] = {
        ".com",
        ".net",
        ".org",
        ".info",
        ".biz",
        ".co",
        ".io",
        ".me",
        ".us",
        ".uk",
        ".de",
        ".fr",
        ".nl",
        ".se",
        ".no",
        ".fi",
        ".es",
        ".it",
        ".pl",
        ".cz"
    };

    constexpr size_t COMMON_TLD_COUNT =
        sizeof(COMMON_TLDS) / sizeof(COMMON_TLDS[0]);

    uint64_t month = Util::GetUTCMonthSinceEpoch();
    uint64_t state = DGA_SEED ^ month ^ idx;

    static const char alphabet[] = "abcdefghijklmnopqrstuvwxyz";

    std::string name;
    name.reserve(20);

    int len = 10 + (Util::SplitMix64(state) % 6); // 10–15 chars

    for (int i = 0; i < len; ++i)
        name += alphabet[Util::SplitMix64(state) % 26];

    const char* tld =
        COMMON_TLDS[Util::SplitMix64(state) % COMMON_TLD_COUNT];

    return name + std::string(tld);
}


bool try_dga_bootstrap(std::vector<uint32_t>& outIPs)
{
	outIPs.reserve(DGA_DOMAIN_COUNT);
    for (size_t i = 0; i < DGA_DOMAIN_COUNT; ++i)
    {
        std::string domain = generate_dga_domain(i);

        ENetAddress addr;
        // NOTE: can be multithreaded/done in a non-blocking way, but shouldnt stall too much, 
        // we're most likely going to hit nearby DNS servers anyway and replication should be a thing. 
        // (although perhaps if said domain doesn't exist it might have to wait further potentially non-regional servers, unless it trusts more regional servers enough for the absence of a registered domain to not look further and cause more delays)
        if (enet_address_set_host(&addr, domain.c_str()) == 0) 
            outIPs.push_back(addr.host);
    }

    return !outIPs.empty();
}

ENetSocket sock;
std::vector<uint32_t> endpointIPs;

void save_known_endpoints_to_cache() {
    // basically it will prioritize those in the endpoint list but not necessarily 
}

void load_known_endpoint_cache() {

}

void send_packet(const void* data, size_t len, ENetAddress addr)
{
    if (len > 1024)
        return;

    ENetBuffer eBuf;
    eBuf.data = const_cast<void*>(data);
    eBuf.dataLength = len;
    enet_socket_send(sock, &addr, &eBuf, 1); // lets not send pings for now
}


void send_text_packet(const char* text, ENetAddress addr)
{
    int strLen = (int)strlen(text);
    if (strLen > 1024)
        return;

    char sendBuf[1024]; // last char is reserved for nullbyte!
    strcpy(sendBuf, text);
    
	send_packet(sendBuf, strLen, addr);
}


size_t scanIndex = 0;
uint64_t lastScanTick = 0;
DiscoveryPacket discoveryPkt;

#define C_BENCHMARK_POW 1

void solve_pow_shani(int num_threads = std::thread::hardware_concurrency()) {
    std::println("Preparing SHA-NI POW...");

    std::atomic<int64_t> found_nonce{ -1 };
    constexpr int64_t CHECK_INTERVAL = 16384;
    constexpr int64_t HASH_STATS_INTERVAL_MS = 1000; // report every second

    POW_Input base_input{};
    base_input.client_seed = Util::GetSecure64();
    base_input.timestamp = Util::GetCurrentUTCSec();

    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    for (int t = 0; t < num_threads; t++) {
        threads.emplace_back([&, t]() {

            alignas(32) POW_Input pow[2];

            int64_t last_check = 0;
            auto last_report = std::chrono::high_resolution_clock::now();
            int64_t local_hashes = 0;

            // Compute a big, separated starting nonce for each thread
            int64_t start_nonce = int64_t(t) * (INT64_MAX / num_threads);
            int64_t end_nonce = int64_t(t + 1) * (INT64_MAX / num_threads);

            for (int64_t nonce = start_nonce; nonce < end_nonce; nonce += 2) 
            {
                if ((nonce - last_check) >= CHECK_INTERVAL) {
                    if (found_nonce.load(std::memory_order_relaxed) != -1) 
                        break;

                    last_check = nonce;
                }

                pow[0] = base_input;
                pow[0].nonce = nonce;
                pow[1] = base_input;
                pow[1].nonce = (nonce + 1);

                auto h = Hash2PowInputs(pow);

                if (h.hashes[0].meets_difficulty_clz(POW_DIFFICULTY_BITS))
                {
                    int64_t expected = -1;
                    if (found_nonce.compare_exchange_strong(expected, nonce, std::memory_order_relaxed))
                        break;
                    
                    break;
                }
                else if (h.hashes[1].meets_difficulty_clz(POW_DIFFICULTY_BITS))
                {
                    int64_t expected = -1;
                    if (found_nonce.compare_exchange_strong(expected, nonce + 1, std::memory_order_relaxed))
                        break;

                    break;
                }

#if C_BENCHMARK_POW == 1
                local_hashes += 2;
                auto now = std::chrono::high_resolution_clock::now();
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_report).count();
                if (elapsed >= HASH_STATS_INTERVAL_MS) {
                    double mh_s = local_hashes / 1e6 / (elapsed / 1000.0);
                    std::println("[Thread {}] {:.3} MH/s", t, mh_s);
                    local_hashes = 0;
                    last_report = now;
                }
#endif
            }
            });
    }

    for (auto& th : threads) 
        th.join();

    POW_Input replay;
    replay = base_input;
    replay.nonce = found_nonce.load();
    discoveryPkt.pow = replay;
	discoveryPkt.hash = HashPowInput(replay);

    std::println("Found Nonce: {}, Hash: {}", discoveryPkt.pow.nonce, discoveryPkt.hash.to_hex());
}

void solve_pow_avx2(int num_threads = std::thread::hardware_concurrency()) {
    std::println("Preparing AVX2 POW...");

    std::atomic<int64_t> found_nonce{ -1 };
    constexpr int64_t CHECK_INTERVAL = 16384;
    constexpr int64_t HASH_STATS_INTERVAL_MS = 1000; // report every second

    POW_Input base_input{};
    base_input.client_seed = Util::GetSecure64();
    base_input.timestamp = Util::GetCurrentUTCSec();

    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    // TODO
}

void solve_pow_generic(int num_threads = std::thread::hardware_concurrency()) {
    std::println("Preparing Generic POW...");

    std::atomic<int64_t> found_nonce{ -1 };
    constexpr int64_t CHECK_INTERVAL = 16384;
    constexpr int64_t HASH_STATS_INTERVAL_MS = 1000; // report every second

    POW_Input base_input{};
    base_input.client_seed = Util::GetSecure64();
    base_input.timestamp = Util::GetCurrentUTCSec();

    std::vector<std::thread> threads;
    threads.reserve(num_threads);

    // TODO
}


void solve_pow() {
    if (cpu_supports_sha())
        solve_pow_shani();
    else if (cpu_supports_avx2())
        solve_pow_avx2();
    else
        solve_pow_generic();
}

void send_discovery_probe()
{
    if (scanIndex == 0)
        solve_pow(); // solve it on every re-scan. TODO make it deferred by 30 seconds or so to give servers at the edge of the list to respond before we refresh our POW challenge which is important for the signatures.

    ENetAddress addr{};
    addr.host = endpointIPs[scanIndex++];
    addr.port = DISCOVERY_PORT;

    if (scanIndex >= endpointIPs.size())
    {
        scanIndex = 0; // loop forever
    }

	send_packet(&discoveryPkt, sizeof(discoveryPkt), addr);
}


void build_endpoints(const std::vector<uint32_t>& cachedEndpointIPs = {})
{
    std::println("Building endpoints...");

    endpointIPs.clear();
    endpointIPs.reserve(1u << 24);

    for (auto ip : cachedEndpointIPs)
        endpointIPs.push_back(ip);

    size_t cachedCount = endpointIPs.size();

    for (uint32_t a = 0; a < 256; ++a)
        for (uint32_t b = 0; b < 256; ++b)
            for (uint32_t c = 0; c < 256; ++c)
            {
                uint32_t ip =
                    (C_FIRST_OCTET << 24) |
                    (a << 16) |
                    (b << 8) |
                    c;

                endpointIPs.push_back(htonl(ip));
            }

    std::println("Built {} endpoints, shuffling...", endpointIPs.size());
    std::shuffle(endpointIPs.begin() + cachedCount, endpointIPs.end(), Util::GetRNG()); // shuffle only the IP/8 stuff based on our first octet.
    std::println("Shuffling done!");
}

#define C_DGA_BOOTSTRAP_ENABLED 1

void init()
{ 
 
    std::srand((uint32_t)Util::MixTriple64(clock(), time(NULL), getpid()));

    enet_initialize();
    sock = enet_socket_create(ENET_SOCKET_TYPE_DATAGRAM);

    if (sock != ENET_SOCKET_NULL)
    {
        enet_socket_set_option(sock, ENET_SOCKOPT_NONBLOCK, 1);
        enet_socket_set_option(sock, ENET_SOCKOPT_RCVBUF, 128 * 1024 * 64);
        enet_socket_set_option(sock, ENET_SOCKOPT_SNDBUF, 128 * 1024 * 64);
    }

    std::vector<uint32_t> dgaIPs;
#if C_DGA_BOOTSTRAP_ENABLED == 1
    try_dga_bootstrap(dgaIPs);
    printf("dga bootstrap done!\n");
#endif

    
    build_endpoints(dgaIPs);
}

std::unordered_set<enet_uint32> ipsKnown;
void process_packet(uint8_t* bytes, int byteLen, ENetAddress eAddr)
{
    if (byteLen < sizeof(DiscoveryResponse))
        return;

    DiscoveryResponse resp;
    memcpy(&resp, bytes, sizeof(resp));

    // reconstruct the exact packet that should have been signed
    DiscoveryPacket pkt = discoveryPkt;
    pkt.pow.ipv4 = eAddr.host; // server should have put their own public IP in here for the signature.

    // verify using ONLY the trusted public key
    if (!verify_ed25519_signature(
        reinterpret_cast<const unsigned char*>(&pkt),
        sizeof(pkt),
        resp.signature,
        TRUSTED_PUBLIC_KEY))
        return;


    // Prevent duplicates early
    if (!ipsKnown.insert(eAddr.host).second)
        return;

    IPAddress ip(eAddr.host);

    std::println("[+] Verified trusted endpoint: {}", ip.GetAsString());

    try {
        Util::AppendToFile("discovered_endpoints.txt",
            ip.GetAsString() + "\n");
    }
    catch (...) {}


	// now, remember the endpoint. this is it, actual communication layer should be user-defined, ideally the flow is also asymmetrically encrypted (think of mitm), but that's up to the user to implement.
    // ideally the discovery scanning still continues in the background regardless to keep discovering more and more endpoints if available (redundancy), 
    // just because we have one IP doesn't mean that further communication on it will be too stable...
}



uint32_t lastSendTick = 0;
bool bStartSleep = false;

void tick()
{
    uint32_t now = time(NULL);
    static uint32_t lastFlush = 0, lastSend = 0;

    if (now != lastSend)
    {
        lastSend = now;
        for (size_t i = 0; i < SCAN_RATE_PER_SEC; ++i) // to be CGNAT conform
            send_discovery_probe();
    }

    // Periodic persistence hook
    if (now - lastFlush > CACHE_FLUSH_INTERVAL)
    {
        lastFlush = now;
        std::println("[*] Known endpoints: {}", ipsKnown.size());
    }
}


void run()
{
    std::println("Running main loop...");

    ENetAddress senderAddr;
    ENetBuffer recvBuf;
    uint8_t recvData[1024];

    recvBuf.data = recvData;
    recvBuf.dataLength = sizeof(recvData);

    while (true)
    {
        int recvLen = enet_socket_receive(sock, &senderAddr, &recvBuf, 1);
        if (recvLen > 0)
        {
            process_packet(recvData, recvLen, senderAddr);
        }

        tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

int main(int argc, char* argv[])
{
    init();
    tick();
    run();
   
    return 0;
}