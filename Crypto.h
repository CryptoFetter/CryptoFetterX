#include <botan/secmem.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/filters.h>
#include <botan/hex.h>
#include <botan/kdf.h>
#include <botan/pwdhash.h>
#include <botan/system_rng.h>
#include <botan/compression.h>

#include <include/bzlib.h>

#include <bitset>
#include <fstream>
#include <vector>

constexpr int ERROR_KDF_STRENGTH = 0x00000071;
constexpr int ERROR_KEYFILE_MISSING = 0x00000072;
constexpr int ERROR_DERIVE_KEY = 0x00000073;

enum FlagsCrypto {
    DENIABILITY = 0,
    COMPRESS = 1,
    HEADER = 2,
    ENCRYPT = 3,
    DECRYPT = 4,
    KEYFILE = 5
};

class CryptoManager {

    static const int IV_SIZE = 16;
    static const int NONCE = 16;
    static const int KEY_SIZE = 32;
    static const int SALT_SIZE = 64;
    static const int HEADER_SIZE = 105;

    struct EncryptFetterHeader {
        Botan::secure_vector<uint8_t> salt;
        Botan::secure_vector<uint8_t> iv;
    };

    Botan::secure_vector<uint8_t> getHashFile(
        std::string file,
        std::string algo
    );

public:

    std::string cipherAlgo;
    bool compressFlag;

    std::bitset<6> crypto_flags;

    std::vector<std::string> kdf;
    std::vector<std::string> algorithms;

    struct KdfParameters {
        uint32_t kdf_strength;
        uint32_t memory;
        uint32_t time;
        uint32_t parallelism;
    }kdf_params;

    struct KeyParameters {
        Botan::secure_vector<uint8_t> key;
        Botan::secure_vector<uint8_t> salt;
        Botan::secure_vector<uint8_t> iv;
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

    unsigned int deriveKeyFromPassword(
        const std::string& password,
        KdfParameters& param,
        KeyParameters& keydata,
        const std::bitset<6>& flag,
        const std::string& kdf,
        const std::string& keyfile
    );

    void encryptFile(
        const std::string& inputFilename,
        const std::string& outputFilename,
        const KeyParameters& keyparams,
        const std::string& selectedCipher,
        const std::bitset<6>& flag,
        const OptionalFetterHeader* header = nullptr
    );

    void decryptFile(
        const std::string& inputFilename,
        const std::string& outputFilename,
        const KeyParameters& keyparams,
        const std::string& selectedCipher,
        const std::bitset<6>& flag,
        bool& stop,
        const OptionalFetterHeader* header = nullptr
    );

    bool getKeyParameters(
        const std::string& inputFilename,
        KeyParameters& keyparams,
        OptionalFetterHeader* header = nullptr
    );

    OptionalFetterHeader createEncryptFileHeader(
        uint8_t version,
        uint8_t encrID,
        uint8_t kdfID,
        uint8_t kdfStrength,
        uint8_t compressFlag,
        uint8_t keyfileFlag
    );

    double calculateEntropy(const std::string& password);

    CryptoManager(const std::vector<std::string>& kdfInit, const std::vector<std::string>& algorithmsInit)
        : kdf(kdfInit), algorithms(algorithmsInit) {
    }

    CryptoManager(){}
};