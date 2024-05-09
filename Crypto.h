#ifndef CRYPTO_H
#define CRYPTO_H

#include "botan/aead.h"
#include "botan/auto_rng.h"
#include "botan/block_cipher.h"
#include "botan/cipher_mode.h"
#include <botan/filters.h>
#include "botan/hash.h"
#include "botan/hex.h"
#include "botan/rng.h"
#include "botan/kdf.h"
#include "botan/pwdhash.h"
#include "botan/secmem.h"
#include "botan/system_rng.h"

#include "botan/bzip2.h"

#include <wx/wx.h>

#include <iostream>
#include <fstream>
#include <array>
#include <vector>
#include <cmath>
#include <map>
#include <set>
#include <unordered_set>
#include <bitset>

#define IV_SIZE 16
#define NONCE 16
#define KEY_SIZE 32
#define SALT_SIZE 64

enum Flags {
	ENCRYPT = 0,
	DECRYPT = 1,
	KEYFILE = 2
};

struct KdfParameters {
	uint32_t kdf_strenth;

	uint32_t memory;
	uint32_t time;

	uint32_t parallelism;
};

struct KeyParameters {
	uint32_t cipher_id;

	Botan::secure_vector<uint8_t> key;
	Botan::secure_vector<uint8_t> salt;
	Botan::secure_vector<uint8_t> iv;
};

const std::string algorithms[] = {"AES-256/GCM(16)", "Serpent/GCM(16)", "Twofish/GCM(16)", "Camellia-256/GCM(16)"};

const std::string kdf[] = { "Argon2id", "Scrypt" };

Botan::secure_vector<uint8_t> getHashFile(std::string file, std::string algo);
void derive_key_from_password(const std::string& password, KdfParameters& param, KeyParameters& keydata, std::bitset<3> &flag, const std::string& kdf, const std::string& keyfile);
void encryptFile(const std::string& inputFilename, const std::string& outputFilename, const KeyParameters& keyparams, wxGauge* gauge, const std::string& selectedCipher);
void decryptFile(const std::string& inputFilename, const std::string& outputFilename, const KeyParameters& keyparams, wxGauge* gauge, const std::string& selectedCipher, bool deniabilityFlag, bool& stop);
void getKeyParameters(const std::string& inputFilename, KeyParameters& keyparams);

double calculateEntropy(const std::string& password);
#endif