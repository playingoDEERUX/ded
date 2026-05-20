#pragma once
#include <string>
#include <sstream>
#include <iomanip>
#include <cstdint>
#include <vector>
#include <immintrin.h>
#include <intrin.h>
#include <bit>
#include <concepts>

#ifndef DISABLE_BUILTIN_BSWAPS
#  if defined __has_builtin
#    if __has_builtin(__builtin_bswap16)
#      define bitcoin_builtin_bswap16(x) __builtin_bswap16(x)
#    endif
#    if __has_builtin(__builtin_bswap32)
#      define bitcoin_builtin_bswap32(x) __builtin_bswap32(x)
#    endif
#    if __has_builtin(__builtin_bswap64)
#      define bitcoin_builtin_bswap64(x) __builtin_bswap64(x)
#    endif
#  elif defined(_MSC_VER)
#      define bitcoin_builtin_bswap16(x) _byteswap_ushort(x)
#      define bitcoin_builtin_bswap32(x) _byteswap_ulong(x)
#      define bitcoin_builtin_bswap64(x) _byteswap_uint64(x)
#  endif
#endif

// MSVC's _byteswap_* functions are not constexpr

#ifndef _MSC_VER
#define BSWAP_CONSTEXPR constexpr
#else
#define BSWAP_CONSTEXPR
#endif

inline BSWAP_CONSTEXPR uint16_t internal_bswap_16(uint16_t x)
{
#ifdef bitcoin_builtin_bswap16
    return bitcoin_builtin_bswap16(x);
#else
    return (x >> 8) | (x << 8);
#endif
}

inline BSWAP_CONSTEXPR uint32_t internal_bswap_32(uint32_t x)
{
#ifdef bitcoin_builtin_bswap32
    return bitcoin_builtin_bswap32(x);
#else
    return (((x & 0xff000000U) >> 24) | ((x & 0x00ff0000U) >> 8) |
        ((x & 0x0000ff00U) << 8) | ((x & 0x000000ffU) << 24));
#endif
}

inline BSWAP_CONSTEXPR uint64_t internal_bswap_64(uint64_t x)
{
#ifdef bitcoin_builtin_bswap64
    return bitcoin_builtin_bswap64(x);
#else
    return (((x & 0xff00000000000000ull) >> 56)
        | ((x & 0x00ff000000000000ull) >> 40)
        | ((x & 0x0000ff0000000000ull) >> 24)
        | ((x & 0x000000ff00000000ull) >> 8)
        | ((x & 0x00000000ff000000ull) << 8)
        | ((x & 0x0000000000ff0000ull) << 24)
        | ((x & 0x000000000000ff00ull) << 40)
        | ((x & 0x00000000000000ffull) << 56));
#endif
}

__forceinline BSWAP_CONSTEXPR uint16_t htobe16_internal(uint16_t host_16bits)
{
    if constexpr (std::endian::native == std::endian::little) return internal_bswap_16(host_16bits);
    else return host_16bits;
}
__forceinline BSWAP_CONSTEXPR uint16_t htole16_internal(uint16_t host_16bits)
{
    if constexpr (std::endian::native == std::endian::big) return internal_bswap_16(host_16bits);
    else return host_16bits;
}
__forceinline BSWAP_CONSTEXPR uint16_t be16toh_internal(uint16_t big_endian_16bits)
{
    if constexpr (std::endian::native == std::endian::little) return internal_bswap_16(big_endian_16bits);
    else return big_endian_16bits;
}
__forceinline BSWAP_CONSTEXPR uint16_t le16toh_internal(uint16_t little_endian_16bits)
{
    if constexpr (std::endian::native == std::endian::big) return internal_bswap_16(little_endian_16bits);
    else return little_endian_16bits;
}
__forceinline BSWAP_CONSTEXPR uint32_t htobe32_internal(uint32_t host_32bits)
{
    if constexpr (std::endian::native == std::endian::little) return internal_bswap_32(host_32bits);
    else return host_32bits;
}
__forceinline BSWAP_CONSTEXPR uint32_t htole32_internal(uint32_t host_32bits)
{
    if constexpr (std::endian::native == std::endian::big) return internal_bswap_32(host_32bits);
    else return host_32bits;
}
__forceinline BSWAP_CONSTEXPR uint32_t be32toh_internal(uint32_t big_endian_32bits)
{
    if constexpr (std::endian::native == std::endian::little) return internal_bswap_32(big_endian_32bits);
    else return big_endian_32bits;
}
__forceinline BSWAP_CONSTEXPR uint32_t le32toh_internal(uint32_t little_endian_32bits)
{
    if constexpr (std::endian::native == std::endian::big) return internal_bswap_32(little_endian_32bits);
    else return little_endian_32bits;
}
__forceinline BSWAP_CONSTEXPR uint64_t htobe64_internal(uint64_t host_64bits)
{
    if constexpr (std::endian::native == std::endian::little) return internal_bswap_64(host_64bits);
    else return host_64bits;
}
__forceinline BSWAP_CONSTEXPR uint64_t htole64_internal(uint64_t host_64bits)
{
    if constexpr (std::endian::native == std::endian::big) return internal_bswap_64(host_64bits);
    else return host_64bits;
}
__forceinline BSWAP_CONSTEXPR uint64_t be64toh_internal(uint64_t big_endian_64bits)
{
    if constexpr (std::endian::native == std::endian::little) return internal_bswap_64(big_endian_64bits);
    else return big_endian_64bits;
}
__forceinline BSWAP_CONSTEXPR uint64_t le64toh_internal(uint64_t little_endian_64bits)
{
    if constexpr (std::endian::native == std::endian::big) return internal_bswap_64(little_endian_64bits);
    else return little_endian_64bits;
}


template <typename B>
concept ByteType = std::same_as<B, unsigned char> || std::same_as<B, std::byte>;

template <ByteType B>
inline uint16_t ReadLE16(const B* ptr)
{
    uint16_t x;
    memcpy(&x, ptr, 2);
    return le16toh_internal(x);
}

template <ByteType B>
inline uint32_t ReadLE32(const B* ptr)
{
    uint32_t x;
    memcpy(&x, ptr, 4);
    return le32toh_internal(x);
}

template <ByteType B>
inline uint64_t ReadLE64(const B* ptr)
{
    uint64_t x;
    memcpy(&x, ptr, 8);
    return le64toh_internal(x);
}

template <ByteType B>
inline void WriteLE16(B* ptr, uint16_t x)
{
    uint16_t v = htole16_internal(x);
    memcpy(ptr, &v, 2);
}

template <ByteType B>
inline void WriteLE32(B* ptr, uint32_t x)
{
    uint32_t v = htole32_internal(x);
    memcpy(ptr, &v, 4);
}

template <ByteType B>
inline void WriteLE64(B* ptr, uint64_t x)
{
    uint64_t v = htole64_internal(x);
    memcpy(ptr, &v, 8);
}

template <ByteType B>
inline uint16_t ReadBE16(const B* ptr)
{
    uint16_t x;
    memcpy(&x, ptr, 2);
    return be16toh_internal(x);
}

template <ByteType B>
inline uint32_t ReadBE32(const B* ptr)
{
    uint32_t x;
    memcpy(&x, ptr, 4);
    return be32toh_internal(x);
}

template <ByteType B>
inline uint64_t ReadBE64(const B* ptr)
{
    uint64_t x;
    memcpy(&x, ptr, 8);
    return be64toh_internal(x);
}

template <ByteType B>
inline void WriteBE16(B* ptr, uint16_t x)
{
    uint16_t v = htobe16_internal(x);
    memcpy(ptr, &v, 2);
}

template <ByteType B>
inline void WriteBE32(B* ptr, uint32_t x)
{
    uint32_t v = htobe32_internal(x);
    memcpy(ptr, &v, 4);
}

template <ByteType B>
inline void WriteBE64(B* ptr, uint64_t x)
{
    uint64_t v = htobe64_internal(x);
    memcpy(ptr, &v, 8);
}

namespace sha256 {
    uint32_t __forceinline Ch(uint32_t x, uint32_t y, uint32_t z) { return z ^ (x & (y ^ z)); }
    uint32_t __forceinline Maj(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (z & (x | y)); }
    uint32_t __forceinline Sigma0(uint32_t x) { return (x >> 2 | x << 30) ^ (x >> 13 | x << 19) ^ (x >> 22 | x << 10); }
    uint32_t __forceinline Sigma1(uint32_t x) { return (x >> 6 | x << 26) ^ (x >> 11 | x << 21) ^ (x >> 25 | x << 7); }
    uint32_t __forceinline sigma0(uint32_t x) { return (x >> 7 | x << 25) ^ (x >> 18 | x << 14) ^ (x >> 3); }
    uint32_t __forceinline sigma1(uint32_t x) { return (x >> 17 | x << 15) ^ (x >> 19 | x << 13) ^ (x >> 10); }

    /** One round of SHA-256. */
    void __forceinline Round(uint32_t a, uint32_t b, uint32_t c, uint32_t& d, uint32_t e, uint32_t f, uint32_t g, uint32_t& h, uint32_t k)
    {
        uint32_t t1 = h + Sigma1(e) + Ch(e, f, g) + k;
        uint32_t t2 = Sigma0(a) + Maj(a, b, c);
        d += t1;
        h = t1 + t2;
    }

    extern void Transform(unsigned char* out, const unsigned char* in);
}

namespace {

    alignas(__m128i) const uint8_t MASK[16] = { 0x03, 0x02, 0x01, 0x00, 0x07, 0x06, 0x05, 0x04, 0x0b, 0x0a, 0x09, 0x08, 0x0f, 0x0e, 0x0d, 0x0c };
    alignas(__m128i) const uint8_t INIT0[16] = { 0x8c, 0x68, 0x05, 0x9b, 0x7f, 0x52, 0x0e, 0x51, 0x85, 0xae, 0x67, 0xbb, 0x67, 0xe6, 0x09, 0x6a };
    alignas(__m128i) const uint8_t INIT1[16] = { 0x19, 0xcd, 0xe0, 0x5b, 0xab, 0xd9, 0x83, 0x1f, 0x3a, 0xf5, 0x4f, 0xa5, 0x72, 0xf3, 0x6e, 0x3c };

    void __forceinline QuadRound(__m128i& state0, __m128i& state1, uint64_t k1, uint64_t k0)
    {
        const __m128i msg = _mm_set_epi64x(k1, k0);
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(msg, 0x0e));
    }

    void __forceinline QuadRound(__m128i& state0, __m128i& state1, __m128i m, uint64_t k1, uint64_t k0)
    {
        const __m128i msg = _mm_add_epi32(m, _mm_set_epi64x(k1, k0));
        state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
        state0 = _mm_sha256rnds2_epu32(state0, state1, _mm_shuffle_epi32(msg, 0x0e));
    }

    void __forceinline ShiftMessageA(__m128i& m0, __m128i m1)
    {
        m0 = _mm_sha256msg1_epu32(m0, m1);
    }

    void __forceinline ShiftMessageC(__m128i& m0, __m128i m1, __m128i& m2)
    {
        m2 = _mm_sha256msg2_epu32(_mm_add_epi32(m2, _mm_alignr_epi8(m1, m0, 4)), m1);
    }

    void __forceinline ShiftMessageB(__m128i& m0, __m128i m1, __m128i& m2)
    {
        ShiftMessageC(m0, m1, m2);
        ShiftMessageA(m0, m1);
    }

    void __forceinline Shuffle(__m128i& s0, __m128i& s1)
    {
        const __m128i t1 = _mm_shuffle_epi32(s0, 0xB1);
        const __m128i t2 = _mm_shuffle_epi32(s1, 0x1B);
        s0 = _mm_alignr_epi8(t1, t2, 0x08);
        s1 = _mm_blend_epi16(t2, t1, 0xF0);
    }

    void __forceinline Unshuffle(__m128i& s0, __m128i& s1)
    {
        const __m128i t1 = _mm_shuffle_epi32(s0, 0x1B);
        const __m128i t2 = _mm_shuffle_epi32(s1, 0xB1);
        s0 = _mm_blend_epi16(t1, t2, 0xF0);
        s1 = _mm_alignr_epi8(t2, t1, 0x08);
    }

    __m128i __forceinline Load(const unsigned char* in)
    {
        return _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)in), _mm_load_si128((const __m128i*)MASK));
    }

    void __forceinline Save(unsigned char* out, __m128i s)
    {
        _mm_storeu_si128((__m128i*)out, _mm_shuffle_epi8(s, _mm_load_si128((const __m128i*)MASK)));
    }
}

namespace sha256_x86_shani {
    extern void Transform(uint32_t* s, const unsigned char* chunk, size_t blocks);
}

namespace sha256d64_x86_shani {

    extern void Transform_2way(unsigned char* out, const unsigned char* in);

}

namespace sha256d64_avx2 {
    namespace {
        __forceinline __m256i K(uint32_t x) { return _mm256_set1_epi32(x); }

        __forceinline __m256i Add(__m256i x, __m256i y) { return _mm256_add_epi32(x, y); }
        __forceinline __m256i Add(__m256i x, __m256i y, __m256i z) { return Add(Add(x, y), z); }
        __forceinline __m256i Add(__m256i x, __m256i y, __m256i z, __m256i w) { return Add(Add(x, y), Add(z, w)); }
        __forceinline __m256i Add(__m256i x, __m256i y, __m256i z, __m256i w, __m256i v) { return Add(Add(x, y, z), Add(w, v)); }
        __forceinline __m256i Inc(__m256i& x, __m256i y) { x = Add(x, y); return x; }
        __forceinline __m256i Inc(__m256i& x, __m256i y, __m256i z) { x = Add(x, y, z); return x; }
        __forceinline __m256i Inc(__m256i& x, __m256i y, __m256i z, __m256i w) { x = Add(x, y, z, w); return x; }
        __forceinline __m256i Xor(__m256i x, __m256i y) { return _mm256_xor_si256(x, y); }
        __forceinline __m256i Xor(__m256i x, __m256i y, __m256i z) { return Xor(Xor(x, y), z); }
        __forceinline __m256i Or(__m256i x, __m256i y) { return _mm256_or_si256(x, y); }
        __forceinline __m256i And(__m256i x, __m256i y) { return _mm256_and_si256(x, y); }
        __forceinline __m256i ShR(__m256i x, int n) { return _mm256_srli_epi32(x, n); }
        __forceinline __m256i ShL(__m256i x, int n) { return _mm256_slli_epi32(x, n); }

        __forceinline __m256i Ch(__m256i x, __m256i y, __m256i z) { return Xor(z, And(x, Xor(y, z))); }
        __forceinline __m256i Maj(__m256i x, __m256i y, __m256i z) { return Or(And(x, y), And(z, Or(x, y))); }
        __forceinline __m256i Sigma0(__m256i x) { return Xor(Or(ShR(x, 2), ShL(x, 30)), Or(ShR(x, 13), ShL(x, 19)), Or(ShR(x, 22), ShL(x, 10))); }
        __forceinline  __m256i Sigma1(__m256i x) { return Xor(Or(ShR(x, 6), ShL(x, 26)), Or(ShR(x, 11), ShL(x, 21)), Or(ShR(x, 25), ShL(x, 7))); }
        __forceinline  __m256i sigma0(__m256i x) { return Xor(Or(ShR(x, 7), ShL(x, 25)), Or(ShR(x, 18), ShL(x, 14)), ShR(x, 3)); }
        __forceinline  __m256i sigma1(__m256i x) { return Xor(Or(ShR(x, 17), ShL(x, 15)), Or(ShR(x, 19), ShL(x, 13)), ShR(x, 10)); }

         __forceinline uint32_t ReadLE32(const unsigned char* p) {
            return  (uint32_t)p[0]
                | ((uint32_t)p[1] << 8)
                | ((uint32_t)p[2] << 16)
                | ((uint32_t)p[3] << 24);
        }

        __forceinline void WriteLE32(unsigned char* p, uint32_t v) {
            p[0] = (unsigned char)(v);
            p[1] = (unsigned char)(v >> 8);
            p[2] = (unsigned char)(v >> 16);
            p[3] = (unsigned char)(v >> 24);
        }

        __forceinline __m256i Read8(const unsigned char* chunk, int offset) {
            __m256i ret = _mm256_set_epi32(
                ReadLE32(chunk + 0 + offset),
                ReadLE32(chunk + 64 + offset),
                ReadLE32(chunk + 128 + offset),
                ReadLE32(chunk + 192 + offset),
                ReadLE32(chunk + 256 + offset),
                ReadLE32(chunk + 320 + offset),
                ReadLE32(chunk + 384 + offset),
                ReadLE32(chunk + 448 + offset)
            );
            return _mm256_shuffle_epi8(ret, _mm256_set_epi32(0x0C0D0E0FUL, 0x08090A0BUL, 0x04050607UL, 0x00010203UL, 0x0C0D0E0FUL, 0x08090A0BUL, 0x04050607UL, 0x00010203UL));
        }

        __forceinline void Write8(unsigned char* out, int offset, __m256i v) {
            v = _mm256_shuffle_epi8(v, _mm256_set_epi32(0x0C0D0E0FUL, 0x08090A0BUL, 0x04050607UL, 0x00010203UL, 0x0C0D0E0FUL, 0x08090A0BUL, 0x04050607UL, 0x00010203UL));
            WriteLE32(out + 0 + offset, _mm256_extract_epi32(v, 7));
            WriteLE32(out + 32 + offset, _mm256_extract_epi32(v, 6));
            WriteLE32(out + 64 + offset, _mm256_extract_epi32(v, 5));
            WriteLE32(out + 96 + offset, _mm256_extract_epi32(v, 4));
            WriteLE32(out + 128 + offset, _mm256_extract_epi32(v, 3));
            WriteLE32(out + 160 + offset, _mm256_extract_epi32(v, 2));
            WriteLE32(out + 192 + offset, _mm256_extract_epi32(v, 1));
            WriteLE32(out + 224 + offset, _mm256_extract_epi32(v, 0));
        }

        /** One round of SHA-256. */
        __forceinline void Round(__m256i a, __m256i b, __m256i c, __m256i& d, __m256i e, __m256i f, __m256i g, __m256i& h, __m256i k)
        {
            __m256i t1 = Add(h, Sigma1(e), Ch(e, f, g), k);
            __m256i t2 = Add(Sigma0(a), Maj(a, b, c));
            d = Add(d, t1);
            h = Add(t1, t2);
        }
    }

    extern void Transform_8way(unsigned char* out, const unsigned char* in);
}

// Decentralized Endpoint Discovery. 




struct alignas(32) POW_Input {
    struct {
        uint8_t prefix[3] = {
            'D','E','D'
        };
        uint8_t version = 1;
    };

    uint32_t ipv4 = 0; // stays 0 for the POW stuff (if not server will reject it), server is expected to set its IPv4 here, and then sign the challenge, set the field to 0 again and send a response. client should then emplace the alleged source ip from the response packet into here and verify the signature with it.
    uint64_t client_seed = 0;
    uint64_t timestamp = 0; // timestamp in secs. also used for expiration, which is 24 hours, after that server/client will reject.
    int64_t nonce = 0;
};
inline unsigned int clz32(uint32_t x) noexcept {
#if defined(_MSC_VER)
    unsigned long index;
    if (_BitScanReverse(&index, x))
        return 31 - index;
    else
        return 32;
#else
    return x == 0 ? 32 : __builtin_clz(x);
#endif
}

struct SHA256d_Hash
{
    uint8_t data[32];

    // Convert hash to hex string
    inline std::string to_hex() const noexcept {
        std::stringstream ss;
        for (int i = 0; i < 32; ++i)
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
        return ss.str();
    }

    inline bool meets_difficulty_clz(uint32_t difficulty_bits) const noexcept
    {
        uint32_t bits = 0;

        for (int i = 0; i < 32; i += 4) {
            uint32_t word =
                (uint32_t(data[i]) << 24) |
                (uint32_t(data[i + 1]) << 16) |
                (uint32_t(data[i + 2]) << 8) |
                (uint32_t(data[i + 3]));

            if (word == 0) {
                bits += 32;
                if (bits >= difficulty_bits)
                    return true;
            }
            else {
                bits += clz32(word);
                return bits >= difficulty_bits;
            }
        }

        return false;
    }
};


struct SHA256d8_Hash
{
    SHA256d_Hash hashes[8];
};

struct SHA256d2_Hash
{
    SHA256d_Hash hashes[2];
};

inline void SHA256D64(unsigned char* out, const unsigned char* in, size_t blocks)
{
    while (blocks >= 8) {
        sha256d64_avx2::Transform_8way(out, in);
        out += 256;
        in += 512;
        blocks -= 8;
    }

    while (blocks >= 2) {
        sha256d64_x86_shani::Transform_2way(out, in);
        out += 64;
        in += 128;
        blocks -= 2;
    }

    while (blocks > 0) {
        sha256::Transform(out, in); // single-block fallback
        out += 32;
        in += 64;
        --blocks;
    }
}

inline void PadHash32ToBlock64(unsigned char* block, const unsigned char* hash32)
{
    memset(block, 0, 64);
    memcpy(block, hash32, 32);
    block[32] = 0x80;

    const uint64_t bit_len = 32 * 8;
    block[56] = (bit_len >> 56) & 0xFF;
    block[57] = (bit_len >> 48) & 0xFF;
    block[58] = (bit_len >> 40) & 0xFF;
    block[59] = (bit_len >> 32) & 0xFF;
    block[60] = (bit_len >> 24) & 0xFF;
    block[61] = (bit_len >> 16) & 0xFF;
    block[62] = (bit_len >> 8) & 0xFF;
    block[63] = bit_len & 0xFF;
}

// quadruple sha256 (double sha256d/sha256q) so we're safe from commercial ASICs unless they spend dozens of $ to make one just for this, but even then it wouldn't matter too much, would just put it back to even playing field:
inline SHA256d8_Hash Hash8PowInputs(const POW_Input* pow)
{
    SHA256d8_Hash result;

    alignas(32) unsigned char blocks[8 * 64] = {};
    alignas(32) unsigned char blocks2[8 * 64] = {};

    // First double SHA
    for (int i = 0; i < 8; ++i) {
        memcpy(blocks + i * 64, &pow[i], sizeof(POW_Input));
        blocks[i * 64 + sizeof(POW_Input)] = 0x80;

        const uint64_t bit_len = sizeof(POW_Input) * 8;
        blocks[i * 64 + 56] = (bit_len >> 56) & 0xFF;
        blocks[i * 64 + 57] = (bit_len >> 48) & 0xFF;
        blocks[i * 64 + 58] = (bit_len >> 40) & 0xFF;
        blocks[i * 64 + 59] = (bit_len >> 32) & 0xFF;
        blocks[i * 64 + 60] = (bit_len >> 24) & 0xFF;
        blocks[i * 64 + 61] = (bit_len >> 16) & 0xFF;
        blocks[i * 64 + 62] = (bit_len >> 8) & 0xFF;
        blocks[i * 64 + 63] = bit_len & 0xFF;
    }

    SHA256D64(reinterpret_cast<unsigned char*>(result.hashes), blocks, 8);

    // Second double SHA (quad total)
    for (int i = 0; i < 8; ++i)
        PadHash32ToBlock64(blocks2 + i * 64,
            reinterpret_cast<unsigned char*>(&result.hashes[i]));

    SHA256D64(reinterpret_cast<unsigned char*>(result.hashes), blocks2, 8);

    return result;
}


// uses SHA-NI instructions
inline SHA256d2_Hash Hash2PowInputs(const POW_Input* pow)
{
    SHA256d2_Hash result;

    alignas(32) unsigned char blocks[2 * 64] = {};
    alignas(32) unsigned char blocks2[2 * 64] = {};

    for (int i = 0; i < 2; ++i) {
        memcpy(blocks + i * 64, &pow[i], sizeof(POW_Input));
        blocks[i * 64 + sizeof(POW_Input)] = 0x80;

        const uint64_t bit_len = sizeof(POW_Input) * 8;
        blocks[i * 64 + 56] = (bit_len >> 56) & 0xFF;
        blocks[i * 64 + 57] = (bit_len >> 48) & 0xFF;
        blocks[i * 64 + 58] = (bit_len >> 40) & 0xFF;
        blocks[i * 64 + 59] = (bit_len >> 32) & 0xFF;
        blocks[i * 64 + 60] = (bit_len >> 24) & 0xFF;
        blocks[i * 64 + 61] = (bit_len >> 16) & 0xFF;
        blocks[i * 64 + 62] = (bit_len >> 8) & 0xFF;
        blocks[i * 64 + 63] = bit_len & 0xFF;
    }

    SHA256D64(reinterpret_cast<unsigned char*>(result.hashes), blocks, 2);

    for (int i = 0; i < 2; ++i)
    {
        PadHash32ToBlock64(blocks2 + i * 64,
            reinterpret_cast<unsigned char*>(&result.hashes[i]));
    }

    SHA256D64(reinterpret_cast<unsigned char*>(result.hashes), blocks2, 2);

    return result;
}


inline SHA256d_Hash HashPowInput(const POW_Input& pow)
{
    SHA256d_Hash result;

    alignas(32) unsigned char block[64] = {};
    alignas(32) unsigned char block2[64] = {};

    memcpy(block, &pow, sizeof(POW_Input));
    block[sizeof(POW_Input)] = 0x80;

    const uint64_t bit_len = sizeof(POW_Input) * 8;
    block[56] = (bit_len >> 56) & 0xFF;
    block[57] = (bit_len >> 48) & 0xFF;
    block[58] = (bit_len >> 40) & 0xFF;
    block[59] = (bit_len >> 32) & 0xFF;
    block[60] = (bit_len >> 24) & 0xFF;
    block[61] = (bit_len >> 16) & 0xFF;
    block[62] = (bit_len >> 8) & 0xFF;
    block[63] = bit_len & 0xFF;

    SHA256D64(reinterpret_cast<unsigned char*>(&result), block, 1);

    PadHash32ToBlock64(block2, reinterpret_cast<unsigned char*>(&result));
    SHA256D64(reinterpret_cast<unsigned char*>(&result), block2, 1);

    return result;
}

