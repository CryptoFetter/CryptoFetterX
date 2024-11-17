#include "EntropyDialog.h"
#include "Secure.h"

std::unique_ptr<Botan::AEAD_Mode> CryptoManager::createCipher(
	const std::string& cipher,
	std::string_view mode,
	const Botan::SymmetricKey& key,
	const Botan::InitializationVector& iv,
	const OptionalFetterHeader* header
) {
	Botan::Cipher_Dir operation;
	if (mode == "Encrypt") {
		operation = Botan::Cipher_Dir::Encryption;
	}
	else if (mode == "Decrypt") {
		operation = Botan::Cipher_Dir::Decryption;
	}
	else {
		throw std::invalid_argument("Invalid mode: " + std::string(mode));
	}

	try {
		auto cipher_mode = Botan::AEAD_Mode::create_or_throw(cipher, operation);

		cipher_mode->set_key(key);

		if (header) {
			std::vector<uint8_t> aad(reinterpret_cast<const uint8_t*>(header),
				reinterpret_cast<const uint8_t*>(header) + HEADER_SIZE);
			cipher_mode->set_associated_data(aad);
		}

		cipher_mode->start(iv);

		return cipher_mode;
	}
	catch (const Botan::Exception& e) {
		throw std::runtime_error("Botan error during cipher creation: " + std::string(e.what()));
	}
	catch (const std::exception& e) {
		throw std::runtime_error("Standard error during cipher creation: " + std::string(e.what()));
	}
	catch (...) {
		throw std::runtime_error("Unknown error occurred during cipher creation");
	}
}

std::unique_ptr<Botan::secure_vector<uint8_t>> CryptoManager::compressData(
	const Botan::secure_vector<uint8_t>& input,
	const std::string& compression_algorithm
) {
	auto compressor = Botan::Compression_Algorithm::create(compression_algorithm);
	if (!compressor) {
		throw std::runtime_error("Invalid compression algorithm: " + compression_algorithm);
	}

	compressor->start(COMPRESS_LEVEL);

	auto output = std::make_unique<Botan::secure_vector<uint8_t>>(input);

	compressor->finish(*output, 0);

	return output;
}

std::unique_ptr<Botan::secure_vector<uint8_t>> CryptoManager::decompressData(
	const Botan::secure_vector<uint8_t>& input,
	const std::string& compression_algorithm
) {
	auto decompressor = Botan::Decompression_Algorithm::create(compression_algorithm);
	if (!decompressor) {
		throw std::runtime_error("Invalid decompression algorithm: " + compression_algorithm);
	}

	decompressor->start();

	auto output = std::make_unique<Botan::secure_vector<uint8_t>>(input);

	decompressor->finish(*output, 0);

	return output;
}

Botan::secure_vector<uint8_t> CryptoManager::getHashFile(
	const std::string& file_path,
	const std::string& algo
)
{
	try {
		std::ifstream file(file_path, std::ios::binary);
		if (!file) {
			throw std::runtime_error("Failed to open file: " + file_path);
		}

		auto hash_fn = Botan::HashFunction::create_or_throw(algo);

		Botan::secure_vector<uint8_t> buffer(4096);
		while (file.read(reinterpret_cast<char*>(buffer.data()), buffer.size()) || file.gcount() > 0) {
			hash_fn->update(buffer.data(), file.gcount());
		}

		return hash_fn->final();
	}
	catch (const std::exception& e) {
		std::cerr << "Error in getHashFile: " << e.what() << std::endl;
		return {};
	}
}

Botan::secure_vector<uint8_t> CryptoManager::getHashData(
	const Botan::secure_vector<uint8_t>& data,
	const std::string& algo
)
{
	try {
		auto hash_fn = Botan::HashFunction::create_or_throw(algo);

		hash_fn->update(data);
		return hash_fn->final();
	}
	catch (const std::exception& e) {
		std::cerr << "Error in getHashData: " << e.what() << std::endl;
		return {};
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
			default: throw std::runtime_error("Invalid KDF strength for Argon2id.");
			}
		}
		else if (kdf == "Scrypt") {
			switch (param.kdf_strength) {
			case 0: param = { 0, 131072, 8, 1 }; break;
			case 1: param = { 1, 524288, 8, 3 }; break;
			case 2: param = { 2, 2097152, 8, 4 }; break;
			default: throw std::runtime_error("Invalid KDF strength for Scrypt.");
			}
		}
		else {
			throw std::runtime_error("Unsupported KDF: " + kdf);
		}

		Botan::PasswordHashFamily::create_or_throw(kdf)->
			from_params(param.memory, param.time, param.parallelism)->
			hash(keydata.key, password, keydata.salt);

		return Crypto::ERROR_OK;
	}
	catch (const Botan::Exception& e) {
		std::cerr << "Botan exception: " << e.what() << std::endl;
		return Crypto::ERROR_DERIVE_KEY;
	}
	catch (const std::runtime_error& e) {
		std::cerr << "Runtime error: " << e.what() << std::endl;
		return Crypto::ERROR_DERIVE_KEY;
	}
	catch (...) {
		std::cerr << "Unknown error occurred during key derivation." << std::endl;
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
) {
	std::ifstream in(inputFilename, std::ios::binary);
	if (!in) {
		std::cerr << "Failed to open input file: " << inputFilename << std::endl;
		return Crypto::ERROR_OPEN_FILE;
	}

	std::ofstream out(outputFilename, std::ios::binary | std::ios::noreplace);
	if (!out) {
		std::cerr << "Failed to open output file: " << outputFilename << std::endl;
		return Crypto::ERROR_OPEN_FILE;
	}

	Botan::secure_vector<uint8_t> buffer((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	if (buffer.empty()) {
		std::cerr << "Input file is empty or could not be read." << std::endl;
		return Crypto::ERROR_OPEN_FILE;
	}

	try {
		Botan::AutoSeeded_RNG rng;
		Botan::SymmetricKey key(keyparams.key.data(), keyparams.key.size());
		Botan::InitializationVector iv(rng, IV_SIZE);
		Botan::secure_vector<uint8_t> iv_bits = iv.bits_of();
		std::unique_ptr<Botan::AEAD_Mode> cryptor = createCipher(selectedCipher, "Encrypt", key, iv, (flag.test(Crypto::HEADER) && header) ? header : nullptr);

		if (flag.test(Crypto::HEADER) && header) {
			out.write(reinterpret_cast<const char*>(header), sizeof(OptionalFetterHeader));
		}

		out.write(reinterpret_cast<const char*>(iv_bits.data()), iv_bits.size());
		if (flag.test(Crypto::KEYFILE)) {
			Botan::secure_vector<uint8_t> salt(SALT_SIZE);
			rng.randomize_with_ts_input(salt.data(), SALT_SIZE);
			out.write(reinterpret_cast<const char*>(salt.data()), salt.size());
		}
		else {
			out.write(reinterpret_cast<const char*>(keyparams.salt.data()), keyparams.salt.size());
		}

		Botan::secure_vector<uint8_t> output_data = flag.test(Crypto::COMPRESS)
			? *compressData(buffer, "bzip2")
			: std::move(buffer);

		cryptor->finish(output_data, 0);
		out.write(reinterpret_cast<const char*>(output_data.data()), output_data.size());

		erase_mem(const_cast<uint8_t*>(keyparams.key.data()), keyparams.key.size());
		return Crypto::ERROR_OK;
	}
	catch (const Botan::Exception& e) {
		std::cerr << "Encryption error: " << e.what() << std::endl;
	}
	catch (const std::exception& e) {
		std::cerr << "Standard exception: " << e.what() << std::endl;
	}
	catch (...) {
		std::cerr << "Unknown error occurred during encryption" << std::endl;
	}

	erase_mem(const_cast<uint8_t*>(keyparams.key.data()), keyparams.key.size());
	return Crypto::ERROR_ENCRYPT;
}

size_t CryptoManager::decryptFile(
	const std::string& inputFilename,
	const std::string& outputFilename,
	const KeyParameters& keyparams,
	const std::string& selectedCipher,
	const std::bitset<7>& flag,
	const std::vector<std::string>& algorithms,
	std::atomic<bool>& stop,
	const OptionalFetterHeader* header
) {
	std::ifstream in(inputFilename, std::ios::in | std::ios::binary);
	if (!in.is_open()) {
		return Crypto::ERROR_OPEN_FILE;
	}

	std::ofstream out(outputFilename, std::ios::out | std::ios::binary);
	if (!out.is_open()) {
		return Crypto::ERROR_OPEN_FILE;
	}

	Botan::SymmetricKey key(keyparams.key.data(), keyparams.key.size());
	Botan::InitializationVector iv(keyparams.iv.data(), keyparams.iv.size());

	size_t seek_position = flag.test(Crypto::HEADER) ? IV_SIZE + SALT_SIZE + HEADER_SIZE : IV_SIZE + SALT_SIZE;
	in.seekg(seek_position, std::ios::beg);

	Botan::secure_vector<uint8_t> buffer((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
	in.close();

	Botan::secure_vector<uint8_t> output_data;

	if (flag.test(Crypto::HEADER)) {
		try {
			std::unique_ptr<Botan::AEAD_Mode> cipher_mode = createCipher(selectedCipher, "Decrypt", key, iv, header);

			if (flag.test(Crypto::COMPRESS)) {
				cipher_mode->finish(buffer);
				output_data = *decompressData(buffer, "bzip2");
				out.write(reinterpret_cast<const char*>(output_data.data()), output_data.size());
			}
			else {
				cipher_mode->finish(buffer);
				out.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
			}

			out.close();
			return Crypto::ERROR_OK;
		}
		catch (const Botan::Invalid_Authentication_Tag&) {
			return Crypto::ERROR_DECRYPT;
		}
	}
	else {

		std::mutex file_mutex;
		std::vector<std::future<void>> futures;

		for (const auto& algorithm : algorithms) {
			if (stop) break;

			futures.emplace_back(std::async(std::launch::async, [&, algorithm]() {
				Botan::secure_vector<uint8_t> temp_buffer = buffer;
				Botan::secure_vector<uint8_t> output_data;

				try {
					std::unique_ptr<Botan::AEAD_Mode> cipher_mode = createCipher(algorithm, "Decrypt", key, iv);
					if (!cipher_mode) {
						throw std::runtime_error("Failed to create cipher mode for algorithm: " + algorithm);
					}

					cipher_mode->finish(temp_buffer);

					try {
						output_data = *decompressData(temp_buffer, "bzip2");

						{
							std::lock_guard<std::mutex> lock(file_mutex);
							out.seekp(0);
							out.write(reinterpret_cast<const char*>(output_data.data()), output_data.size());
						}

						stop = true;
					}
					catch (const Botan::Compression_Error&) {
						std::lock_guard<std::mutex> lock(file_mutex);
						out.seekp(0);
						out.write(reinterpret_cast<const char*>(temp_buffer.data()), temp_buffer.size());
						stop = true;
					}
				}
				catch (const Botan::Invalid_Authentication_Tag&) {
					return;
				}
				catch (...) {
					return;
				}
				}));
		}

		for (auto& future : futures) {
			future.get();
		}

		out.close();
		return stop ? Crypto::ERROR_OK : Crypto::ERROR_DECRYPT;
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

	bool result = (
		byte7 == 0x07 && 
		byte8 == 0x07 && 
		byte9 == 0x07);

	if (result) {
		if (!in.read(reinterpret_cast<char*>(header), sizeof(OptionalFetterHeader))) {
			return false;
		}
	}

	if (!in.read(reinterpret_cast<char*>(iv.data()), IV_SIZE) || 
		!in.read(reinterpret_cast<char*>(salt.data()), SALT_SIZE)) {
		return false;
	}

	keyparams.iv = std::move(iv);
	keyparams.salt = std::move(salt);

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
	OptionalFetterHeader header = {
		version,
		encrID,
		kdfID,
		kdfStrength,
		compressFlag,
		keyfileFlag,
		7, // 
		7, // crypto-marker
		7  //
	};

	std::fill(std::begin(header.reserved), std::end(header.reserved), 0);

	return header;
}

double CryptoManager::calculateEntropy(const std::wstring& password) {
	const int specialCharSize = 32;
	int charsetSize = 0;
	bool hasLowerCase = false, hasUpperCase = false, hasDigit = false, hasSpecialChar = false;
	bool hasConsecutiveCharacters = false;

	std::unordered_set<wchar_t> uniqueChars;

	std::locale loc("");
	for (size_t i = 0; i < password.size(); ++i) {
		wchar_t ch = password[i];
		uniqueChars.insert(ch);

		if (std::islower(ch, loc)) hasLowerCase = true;
		else if (std::isupper(ch, loc)) hasUpperCase = true;
		else if (std::isdigit(ch, loc)) hasDigit = true;
		else hasSpecialChar = true;

		if (i > 0 && password[i] == password[i - 1]) {
			hasConsecutiveCharacters = true;
		}
	}

	charsetSize = (hasLowerCase ? 26 : 0)
		+ (hasUpperCase ? 26 : 0)
		+ (hasDigit ? 10 : 0)
		+ (hasSpecialChar ? specialCharSize : 0);

	int uniqueCharsetSize = uniqueChars.size();
	int effectiveCharsetSize = (uniqueCharsetSize > 0) ? uniqueCharsetSize : 1;

	double entropy = password.length() * std::log2(effectiveCharsetSize);

	if (hasConsecutiveCharacters) {
		entropy *= 0.7;
	}

	return entropy;
}
