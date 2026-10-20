#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

namespace security {

template <size_t N, uint8_t Key = 0xA7>
struct ObfuscatedStorage {
    uint8_t data[N];
};

template <size_t N, uint8_t Key = 0xA7>
constexpr ObfuscatedStorage<N, Key> MakeObfuscated(const char (&str)[N]) {
    ObfuscatedStorage<N, Key> storage{};
    for (size_t i = 0; i < N; ++i) {
        storage.data[i] = static_cast<uint8_t>(static_cast<uint8_t>(str[i]) ^ static_cast<uint8_t>(Key + (i * 11)));
    }
    return storage;
}

template <size_t N, uint8_t Key = 0xA7>
class StackDecryptedString {
private:
    char decrypted_[N];

public:
    inline explicit StackDecryptedString(const ObfuscatedStorage<N, Key>& storage) {
        // Compiler barrier: prevents LLVM/Clang/GCC from constant-folding the XOR decryption
        // back into plaintext in .rodata during -O2/-O3 optimization
        uint8_t k = Key;
        __asm__ volatile ("" : "+r"(k));

        for (size_t i = 0; i < N; ++i) {
            decrypted_[i] = static_cast<char>(storage.data[i] ^ static_cast<uint8_t>(k + (i * 11)));
        }
    }

    inline ~StackDecryptedString() {
        // Volatile pointer prevents compiler dead-store elimination (DSE)
        volatile char* p = decrypted_;
        for (size_t i = 0; i < N; ++i) {
            p[i] = 0;
        }
    }

    inline const char* c_str() const { return decrypted_; }
    inline std::string str() const { return std::string(decrypted_, N > 0 ? N - 1 : 0); }
    inline operator std::string() const { return str(); }
};

} // namespace security

#define OBF_STR(str) ([]() { \
    constexpr auto _obf_storage = ::security::MakeObfuscated<sizeof(str)>(str); \
    return ::security::StackDecryptedString<sizeof(str)>(_obf_storage); \
}())

#define OBF_KEY(str, key) ([]() { \
    constexpr auto _obf_storage = ::security::MakeObfuscated<sizeof(str), key>(str); \
    return ::security::StackDecryptedString<sizeof(str), key>(_obf_storage); \
}())
