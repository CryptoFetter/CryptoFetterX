#include "EntropyDialog.h"

std::unique_ptr<Botan::AEAD_Mode> CryptoManager::createCipher(
	const std::string& cipher, 
	const std::string& mode, 
	const Botan::SymmetricKey& key, 
	const Botan::InitializationVector& iv,
	const OptionalFetterHeader* header
) {
	auto operation = (mode == "Encrypt") ? Botan::Cipher_Dir::Encryption :
		(mode == "Decrypt") ? Botan::Cipher_Dir::Decryption :
		throw std::invalid_argument("Invalid mode: " + mode);

	std::unique_ptr<Botan::AEAD_Mode> cipher_mode;

	try {

	cipher_mode = Botan::AEAD_Mode::create_or_throw(cipher, operation);

	cipher_mode->set_key(key);

	if (header != nullptr) {
		std::vector<uint8_t> aad(sizeof(OptionalFetterHeader));

		std::memcpy(aad.data(), reinterpret_cast<const uint8_t*>(header), sizeof(OptionalFetterHeader));

		cipher_mode->set_associated_data(aad);
	}
	
	cipher_mode->start(iv);

	}
	catch (...) {

		throw std::runtime_error("Failed to create cipher mode");
		return nullptr;
	}

	return cipher_mode;
}

Botan::secure_vector<uint8_t>* CryptoManager::compressData(
	const Botan::secure_vector<uint8_t>& input, 
	const std::string& compression_algorithm
)
{
	std::unique_ptr<Botan::Compression_Algorithm> compressor(Botan::Compression_Algorithm::create(compression_algorithm));
	if (!compressor) {
		throw std::runtime_error("Invalid decompression algorithm: " + compression_algorithm);
	}

	compressor->start(COMPRESS_LEVEL);

	auto output = new Botan::secure_vector<uint8_t>();

	Botan::secure_vector<uint8_t> temp_buf = input;
	compressor->finish(temp_buf, 0);
	output->insert(output->end(), temp_buf.begin(), temp_buf.end());

	return output;
}

Botan::secure_vector<uint8_t>* CryptoManager::decompressData(
	const Botan::secure_vector<uint8_t>& input, 
	const std::string& compression_algorithm
)
{
	std::unique_ptr<Botan::Decompression_Algorithm> decompressor(Botan::Decompression_Algorithm::create(compression_algorithm));
	if (!decompressor) {
		throw std::runtime_error("Invalid decompression algorithm: " + compression_algorithm);
	}

	decompressor->start();

	auto output = new Botan::secure_vector<uint8_t>();

	Botan::secure_vector<uint8_t> temp_buf = input;
	decompressor->finish(temp_buf, 0);
	output->insert(output->end(), temp_buf.begin(), temp_buf.end());

	return output;
}

Botan::secure_vector<uint8_t> CryptoManager::getHashFile(
	const std::string& file_path,
	const std::string& algo
)
{
	try {
		std::vector<uint8_t> buffer;

		std::ifstream keyfile(file_path, std::ios::in | std::ios::binary);
		if (!keyfile.is_open()) {
			throw std::runtime_error("Failed to open file: " + file_path);
		}

		std::copy(std::istreambuf_iterator<char>(keyfile), std::istreambuf_iterator<char>(), std::back_inserter(buffer));
		keyfile.close();

		if (buffer.empty()) { throw std::exception(); }

		return Botan::HashFunction::create_or_throw(algo)->process(buffer.data(), buffer.size());
	}
	catch (...) {
		return Botan::secure_vector<uint8_t>();
	}
}

Botan::secure_vector<uint8_t> CryptoManager::getHashData(
	const Botan::secure_vector<uint8_t>& data,
	const std::string& algo
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

	Botan::secure_vector<uint8_t> buffer;
	Botan::secure_vector<uint8_t> output_data;

	try {

		Botan::AutoSeeded_RNG rng;

		Botan::SymmetricKey key(keyparams.key.data(), keyparams.key.size());

		Botan::InitializationVector iv(rng, IV_SIZE);
		Botan::secure_vector<uint8_t> iv_bits = iv.bits_of();

		std::unique_ptr<Botan::AEAD_Mode> cryptor;

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

		cryptor = createCipher(selectedCipher, "Encrypt", key, iv, flag.test(Crypto::HEADER) && header ? header : nullptr);

		if (flag.test(Crypto::COMPRESS)) {
			output_data = *compressData(buffer, "bzip2");
			cryptor->finish(output_data, 0);
			out.write(reinterpret_cast<const char*>(output_data.data()), output_data.size());
		}
		else {
			cryptor->finish(buffer, 0);
			out.write(reinterpret_cast<const char*>(buffer.data()), buffer.size());
		}

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

			futures.push_back(std::async(std::launch::async, [&, algorithm]() {
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
