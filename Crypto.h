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
#define HEADER_SIZE 105

// Kdf derive flags
enum FlagsEncrypt {
	ENCRYPT = 0,
	DECRYPT = 1,
	KEYFILE = 2,
	HEADER1 = 3

};

// crypto file flags
enum FlagsSettings {
	DENIABILITY = 0,
	COMPRESS = 1,
	HEADER = 2
};

struct KdfParameters {
	uint32_t kdf_strength;

	// Argon1id Scrypt parameters
	uint32_t memory;		// M // N (CPU/Memory cost parameter)
	uint32_t time;			// t // // r (Block size parameter)

	// universal param
	uint32_t parallelism;	// p
};

struct KeyParameters {
	uint32_t cipher_id;

	Botan::secure_vector<uint8_t> key;
	Botan::secure_vector<uint8_t> salt;
	Botan::secure_vector<uint8_t> iv;
};

struct EncryptFileHeader {
	uint8_t version;
	uint8_t encryptionAlgorithmID;
	uint8_t kdfAlgorithmID;
	uint8_t kdfStrength;
	uint8_t compressFlag;
	uint8_t keyfileFlag;

	uint8_t reserved[99];
};

const std::string algorithms[] = {"AES-256/GCM(16)", "Serpent/GCM(16)", "Twofish/GCM(16)", "Camellia-256/GCM(16)"};

const std::string kdf[] = { "Argon2id", "Scrypt" };

Botan::secure_vector<uint8_t> getHashFile(
	_In_	std::string file,
	_In_	std::string algo
);

void derive_key_from_password(
	_In_	const std::string& password,
	_Out_	KdfParameters& param,
	_Out_	KeyParameters& keydata,
	_In_	std::bitset<4> &flag,
	_In_	const std::string& kdf,
	_In_	const std::string& keyfile
);


void encryptFile(
	_In_	const std::string& inputFilename,
	_In_	const std::string& outputFilename,
	_In_	const KeyParameters& keyparams,
	_Out_	wxGauge* gauge,
	_In_	const std::string& selectedCipher,
	_In_	std::bitset<3>& flag,
	_In_	EncryptFileHeader* header = nullptr  // const
);

void decryptFile(
	_In_	const std::string& inputFilename,
	_In_	const std::string& outputFilename,
	_In_	const KeyParameters& keyparams,
	_Out_	wxGauge* gauge,
	_In_	const std::string& selectedCipher,
	_In_	std::bitset<3>& flag,
	_In_	bool& stop,
	_In_	EncryptFileHeader* header = nullptr
);

void getKeyParameters(
	_In_	const std::string& inputFilename,
	_Out_	KeyParameters& keyparams,
	_Out_	EncryptFileHeader* header = nullptr
);

void writeHeaderToFile(const EncryptFileHeader& header, const std::string& fileName);

EncryptFileHeader createEncryptFileHeader(uint8_t version, uint8_t encrID, uint8_t kdfID, uint8_t kdfStrength, uint8_t compressFlag, uint8_t keyfileFlag);

double calculateEntropy(const std::string& password);
#endif