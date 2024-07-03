#include "EntropyDialog.h"

Botan::secure_vector<uint8_t> CryptoManager::getHashFile(
	std::string file_path,
	std::string algo
)
{
	try {
		std::vector<uint8_t> buffer;

		std::ifstream keyfile(file_path, std::ios::in | std::ios::binary);
		if (!keyfile.is_open()){ throw std::exception(); }


		std::copy(std::istreambuf_iterator<char>(keyfile), std::istreambuf_iterator<char>(), std::back_inserter(buffer));
		keyfile.close();

		if(buffer.empty()) { throw std::exception(); }

		return Botan::HashFunction::create_or_throw(algo)->process(buffer.data(), buffer.size());
	}
	catch (...) {
		return Botan::secure_vector<uint8_t>();
	}
}

Botan::secure_vector<uint8_t> CryptoManager::getHashData(
	Botan::secure_vector<uint8_t> data,
	std::string algo
)
{
	try {
		return Botan::HashFunction::create(algo)->process(data.data(), data.size());
	}
	catch (...) {
		return Botan::secure_vector<uint8_t>();
	}
}

size_t CryptoManager::deriveKeyFromPassword(
	const std::string& password,
	KdfParameters& param,
	KeyParameters& keydata,
	const std::bitset<7>& flag,
	const std::string& kdf,
	const std::string& keyfile
)
{
	try {
		Botan::AutoSeeded_RNG rng;

		keydata.key = Botan::secure_vector<uint8_t>(KEY_SIZE);

		if (flag.test(Crypto::ENCRYPT) && !flag.test(Crypto::KEYFILE))
		{
			keydata.salt = Botan::secure_vector<uint8_t>(SALT_SIZE);

			if (flag.test(Crypto::HARD_RNG)) {

				if (!keydata.seed.size()) { throw std::exception(); }

				rng.randomize_with_input(&keydata.salt[0], SALT_SIZE, keydata.seed.data(), keydata.seed.size());
			}
			else {
				rng.randomize_with_ts_input(&keydata.salt[0], SALT_SIZE);
			}
		}

		if ((flag.test(Crypto::ENCRYPT) || flag.test(Crypto::DECRYPT)) && flag.test(Crypto::KEYFILE))
		{
			if (keyfile.empty()) { throw std::exception(); }
				
			keydata.salt = getHashFile(keyfile, "Keccak-1600(512)");

			if (keydata.salt.empty()) { throw std::exception(); }
		}

		if (kdf == "Argon2id") {
			switch (param.kdf_strength) {
			case 0: param = { 0, 131070, 12, 4 }; break;
			case 1: param = { 1, 524280, 22, 4 }; break;
			case 2: param = { 2, 2097120, 32, 4 }; break;
			}
		}
		else if (kdf == "Scrypt") {
			switch (param.kdf_strength) {
			case 0: param = { 0, 131072, 8, 1 }; break;
			case 1: param = { 1, 524288, 8, 3 }; break;
			case 2: param = { 2, 2097152, 8, 4 }; break;
			}
		}

		Botan::PasswordHashFamily::create_or_throw(kdf)->
			from_params(param.memory, param.time, param.parallelism)->
			hash(keydata.key, password, keydata.salt);

		return Crypto::ERROR_OK;
	}
	catch (...) {
		return Crypto::ERROR_DERIVE_KEY;
	}
}

size_t CryptoManager::encryptFile(
	const std::string& inputFilename,
	const std::string& outputFilename,
	const KeyParameters& keyparams,
	const std::string& selectedCipher,
	const std::bitset<7>& flag,
	const OptionalFetterHeader* header
)
{
	std::ifstream in(inputFilename, std::ios::in | std::ios::binary);
	if (!in.is_open()) {
		return Crypto::ERROR_OPEN_FILE;
	}

	std::ofstream out(outputFilename, std::ios::noreplace | std::ios::out | std::ios::binary);
	if (!out.is_open()) {
		in.close();
		return Crypto::ERROR_OPEN_FILE;
	}

	std::vector<uint8_t> buffer;

	try {

	Botan::AutoSeeded_RNG rng;
	std::unique_ptr<Botan::Pipe> pipe;

	Botan::SymmetricKey key(keyparams.key.data(), keyparams.key.size());
	Botan::InitializationVector iv(rng, IV_SIZE);
	Botan::secure_vector<uint8_t> iv_bits = iv.bits_of();

	std::copy(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>(), std::back_inserter(buffer));

	if (flag.test(Crypto::HEADER) && header != nullptr)
	{
		out.write(reinterpret_cast<const char*>(header), sizeof(OptionalFetterHeader));
	}

	if (flag.test(Crypto::KEYFILE)) {
		// When a key file is used, salt is taken from it. But a random salt is still written to the encrypted file, which is not suitable for decrypting data
		Botan::secure_vector<uint8_t> salt = Botan::secure_vector<uint8_t>(SALT_SIZE);
		rng.randomize_with_ts_input(&salt[0], SALT_SIZE);

		out.write(reinterpret_cast<const char*>(iv_bits.data()), iv_bits.size());
		out.write(reinterpret_cast<const char*>(salt.data()), salt.size());
	}
	else {
		out.write(reinterpret_cast<const char*>(iv_bits.data()), iv_bits.size());
		out.write(reinterpret_cast<const char*>(keyparams.salt.data()), keyparams.salt.size());
	}

	if (flag.test(Crypto::COMPRESS)) {
		pipe = std::make_unique<Botan::Pipe>(
			new Botan::Compression_Filter("bzip2", 9),
			Botan::get_cipher(selectedCipher, key, iv, Botan::Cipher_Dir::Encryption),
			new Botan::DataSink_Stream(out));
	} else {
		pipe = std::make_unique<Botan::Pipe>(
			Botan::get_cipher(selectedCipher, key, iv, Botan::Cipher_Dir::Encryption), 
			new Botan::DataSink_Stream(out));
	}

	pipe->process_msg(buffer.data(), buffer.size());

	in.close();
	out.close();
	return Crypto::ERROR_OK;
	}
	catch (...)
	{
		in.close();
		out.close();

		return Crypto::ERROR_ENCRYPT;
	}
}

size_t CryptoManager::decryptFile(
	const std::string& inputFilename,
	const std::string& outputFilename,
	const KeyParameters& keyparams,
	const std::string& selectedCipher,
	const std::bitset<7>& flag,
	bool& stop
) {
	std::vector<uint8_t> buffer;

	std::ifstream in(inputFilename, std::ios::in | std::ios::binary);
	if (!in.is_open()) {
		return Crypto::ERROR_OPEN_FILE;
	}

	std::ofstream out(outputFilename, std::ios::out | std::ios::binary);
	if (!out.is_open()) {
		in.close();
		return Crypto::ERROR_OPEN_FILE;
	}

	Botan::SymmetricKey key(keyparams.key.data(), keyparams.key.size());
	Botan::InitializationVector iv(keyparams.iv.data(), keyparams.iv.size());
	std::unique_ptr<Botan::Pipe> pipe;

	if (flag.test(Crypto::HEADER)) {

		in.seekg(IV_SIZE + SALT_SIZE + HEADER_SIZE);
		std::copy(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>(), std::back_inserter(buffer));
		in.close();
	}
	else {

		in.seekg(IV_SIZE + SALT_SIZE);
		std::copy(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>(), std::back_inserter(buffer));
		in.close();
	}

	if (!flag.test(Crypto::HEADER)) {
		for (const auto& algorithm : algorithms) {
			if (stop) continue;

			for (int attempt = 0; attempt < 2; ++attempt) {

				bool useCompression = (attempt == 0);

				try {
					if (useCompression) {

						pipe.reset();
						pipe = std::make_unique<Botan::Pipe>(
							Botan::get_cipher(algorithm, key, iv, Botan::Cipher_Dir::Decryption),
							new Botan::Decompression_Filter("bzip2", 9),
							new Botan::DataSink_Stream(out)
						);

						compressFlag = true;
					}
					else {
						pipe.reset();
						pipe = std::make_unique<Botan::Pipe>(
							Botan::get_cipher(algorithm, key, iv, Botan::Cipher_Dir::Decryption), 
							new Botan::DataSink_Stream(out));

						compressFlag = false;
					}

					pipe->process_msg(buffer.data(), buffer.size());

					stop = true;
					cipherAlgo = algorithm;

					break;
				}
				catch (Botan::Invalid_Authentication_Tag) {

					out.clear();
					out.seekp(0);
					in.seekg(IV_SIZE + SALT_SIZE);
				}
				catch (Botan::Compression_Error) {

					out.clear();
					out.seekp(0);
					in.seekg(IV_SIZE + SALT_SIZE);
				}
				catch (Botan::Invalid_State) {

					std::vector<uint8_t>().swap(buffer);
					out.close();
					return Crypto::ERROR_DECRYPT;
				}
				catch (...) {

					std::vector<uint8_t>().swap(buffer);
					out.close();
					return Crypto::ERROR_DECRYPT;
				}
			}
		}
	}
	else {
		try {
			if (flag.test(Crypto::COMPRESS)) {

				pipe.reset();
				pipe = std::make_unique<Botan::Pipe>(
					Botan::get_cipher(selectedCipher, key, iv, Botan::Cipher_Dir::Decryption),
					new Botan::Decompression_Filter("bzip2", 9),
					new Botan::DataSink_Stream(out)
				);
			}
			else {

				pipe.reset();
				pipe = std::make_unique<Botan::Pipe>(
					Botan::get_cipher(selectedCipher, key, iv, Botan::Cipher_Dir::Decryption), 
					new Botan::DataSink_Stream(out));
			}

		pipe->process_msg(buffer.data(), buffer.size());

		out.close();

		return Crypto::ERROR_OK;
		}
		catch (Botan::Invalid_Authentication_Tag) {
			out.close();
			return Crypto::ERROR_DECRYPT;
		}
		catch (...) {

			std::vector<uint8_t>().swap(buffer);
			out.close();

			return Crypto::ERROR_DECRYPT;
		}
	}
	return Crypto::ERROR_OK;
}

bool CryptoManager::getKeyParameters(
	const std::string& inputFilename,
	KeyParameters& keyparams,
	OptionalFetterHeader* header
)
{
	std::ifstream in(inputFilename, std::ios::in | std::ios::binary);

	if (!in.is_open()) {
		return false;
	}

	Botan::secure_vector<uint8_t> iv(IV_SIZE);
	Botan::secure_vector<uint8_t> salt(SALT_SIZE);

	in.seekg(6, std::ios::beg);

	char byte7, byte8, byte9;
	in.read(&byte7, 1);
	in.read(&byte8, 1);
	in.read(&byte9, 1);

	in.seekg(0, std::ios::beg);

	bool result = (byte7 == 0x07 && byte8 == 0x07 && byte9 == 0x07);

	if (result) {
		if (!in.read(reinterpret_cast<char*>(header), sizeof(OptionalFetterHeader))) {
			in.close();
			return false;
		}
	}

	if (!in.read(reinterpret_cast<char*>(iv.data()), IV_SIZE) || !in.read(reinterpret_cast<char*>(salt.data()), SALT_SIZE)) {
		in.close();
		return false;
	}

	keyparams.iv = std::move(iv);
	keyparams.salt = std::move(salt);

	in.close();

	return result;
}

CryptoManager::OptionalFetterHeader CryptoManager::createEncryptFileHeader(
	uint8_t version,
	uint8_t encrID,
	uint8_t kdfID,
	uint8_t kdfStrength,
	uint8_t compressFlag,
	uint8_t keyfileFlag
) {
	OptionalFetterHeader header;

	header.version = version;
	header.encryptionAlgorithmID = encrID;
	header.kdfAlgorithmID = kdfID;
	header.kdfStrength = kdfStrength;
	header.compressFlag = compressFlag;
	header.keyfileFlag = keyfileFlag;

	header.marker1 = 7;
	header.marker2 = 7;
	header.marker3 = 7;

	for (int i = 0; i < 96; ++i) {
		header.reserved[i] = 0;
	}

	return header;
}

double CryptoManager::calculateEntropy(const std::string& password) {
	const int specialCharSize = 15;
	int charsetSize = 0;
	bool hasLowerCase = false, hasUpperCase = false, hasDigit = false, hasSpecialChar = false;
	bool hasConsecutiveCharacters = false;

	for (size_t i = 0; i < password.size(); ++i) {
		char ch = password[i];
		if (islower(ch)) hasLowerCase = true;
		else if (isupper(ch)) hasUpperCase = true;
		else if (isdigit(ch)) hasDigit = true;
		else hasSpecialChar = true;

		if (i > 0 && password[i] == password[i - 1]) {
			hasConsecutiveCharacters = true;
			break;
		}
	}

	charsetSize = 0
		+ (hasLowerCase ? 10 : 0)
		+ (hasUpperCase ? 10 : 0)
		+ (hasDigit ? 10 : 0)
		+ (hasSpecialChar ? specialCharSize : 0);

	int effectiveCharsetSize = (charsetSize == 0) ? 1 : charsetSize;

	double entropy = password.length() * std::log2(effectiveCharsetSize);

	if (hasConsecutiveCharacters) {
		entropy /= 2;
	}

	return entropy;
}