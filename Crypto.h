#ifndef CRYPTO_H
#define CRYPTO_H

#include <botan/x509self.h>
#include <botan/frodokem.h>
#include <botan/kyber.h>
#include <botan/pubkey.h>
#include <botan/secmem.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/filters.h>
#include <botan/hex.h>
#include <botan/kdf.h>
#include <botan/pwdhash.h>
#include <botan/system_rng.h>
#include <botan/compression.h>
#include <botan/aead.h>

#include <include/bzlib.h>

#include <bitset>
#include <fstream>
#include <vector>
#include <cmath>
#include <cctype>
#include <string>
#include <string>
#include <locale>
#include <codecvt>
#include <unordered_set>
#include <future>
#include <atomic>

#include <thread>
#include <mutex>

namespace Crypto {

    constexpr int ERROR_KDF_STRENGTH = 0x00000071;
    constexpr int ERROR_KEYFILE_MISSING = 0x00000072;
    constexpr int ERROR_DERIVE_KEY = 0x00000073;
    constexpr int ERROR_DECRYPT = 0x00000074;
    constexpr int ERROR_ENCRYPT = 0x00000075;
    constexpr int ERROR_OPEN_FILE = 0x00000076;
    constexpr int ERROR_OK = 0x00000077;


    enum FlagsCrypto {
        DENIABILITY = 0,
        COMPRESS = 1,
        HEADER = 2,
        ENCRYPT = 3,
        DECRYPT = 4,
        KEYFILE = 5,
        HARD_RNG = 6
    };
}

class CryptoManager {

    struct EncryptFetterHeader {
        Botan::secure_vector<uint8_t> salt;
        Botan::secure_vector<uint8_t> iv;
    };

public:

    std::unique_ptr<Botan::AEAD_Mode> cipher_mode;

    std::string cipherAlgo;
    bool compressFlag;

    std::bitset<7> crypto_flags;

    struct KdfParameters {
        size_t kdf_strength;
        size_t memory;
        size_t time;
        size_t parallelism;
    }kdf_params;

    struct KeyParameters {
        Botan::secure_vector<uint8_t> key;
        Botan::secure_vector<uint8_t> salt;
        Botan::secure_vector<uint8_t> iv;
        Botan::secure_vector<uint8_t> seed;
    }key_params;

    struct OptionalFetterHeader {
        uint8_t version;
        uint8_t encryptionAlgorithmID;
        uint8_t kdfAlgorithmID;
        uint8_t kdfStrength;
        uint8_t compressFlag;
        uint8_t keyfileFlag;
        uint8_t marker1;
        uint8_t marker2;
        uint8_t marker3;
        uint8_t reserved[96];
    }header;

    size_t deriveKeyFromPassword(
        const std::string& password,
        KdfParameters& param,
        KeyParameters& keydata,
        const std::bitset<7>& flag,
        const std::string& kdf,
        const std::string& keyfile
    );

    size_t encryptFile(
        const std::string& inputFilename,
        const std::string& outputFilename,
        const KeyParameters& keyparams,
        const std::string& selectedCipher,
        const std::bitset<7>& flag,
        const OptionalFetterHeader* header = nullptr
    );

    size_t decryptFile(
        const std::string& inputFilename,
        const std::string& outputFilename,
        const KeyParameters& keyparams,
        const std::string& selectedCipher,
        const std::bitset<7>& flag,
        const std::vector<std::string>& algorithms,
        std::atomic<bool> &stop,
        const OptionalFetterHeader* header = nullptr
    );

    bool getKeyParameters(
        const std::string& inputFilename,
        KeyParameters& keyparams,
        OptionalFetterHeader* header = nullptr
    );

    std::unique_ptr<Botan::AEAD_Mode> createCipher(
        const std::string& cipher, 
        const std::string& mode, 
        const Botan::SymmetricKey& key, 
        const Botan::InitializationVector& iv,
        const OptionalFetterHeader* header = nullptr
    );

    Botan::secure_vector<uint8_t>* compressData(
        const Botan::secure_vector<uint8_t>& input, 
        const std::string& compression_algorithm
    );

    Botan::secure_vector<uint8_t>* decompressData(
        const Botan::secure_vector<uint8_t>& input, 
        const std::string& compression_algorithm
    );

    OptionalFetterHeader createEncryptFileHeader(
        uint8_t version,
        uint8_t encrID,
        uint8_t kdfID,
        uint8_t kdfStrength,
        uint8_t compressFlag,
        uint8_t keyfileFlag
    );

    Botan::secure_vector<uint8_t> getHashFile(
        const std::string &file_path,
        const std::string &algo
    );

    Botan::secure_vector<uint8_t> getHashData(
        const Botan::secure_vector<uint8_t> &data,
        const std::string &algo
    );

    double calculateEntropy(const std::wstring& password);

    static const int IV_SIZE = 16;
    static const int KEY_SIZE = 32;
    static const int SALT_SIZE = 64;
    static const int HEADER_SIZE = sizeof(OptionalFetterHeader);

    static const int COMPRESS_LEVEL = 9;

    CryptoManager() = default;
    ~CryptoManager() = default;
};

#endif