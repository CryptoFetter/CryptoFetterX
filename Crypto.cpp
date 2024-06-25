#include "Crypto.h"

Botan::secure_vector<uint8_t> CryptoManager::getHashFile(
	std::string file,
	std::string algo
)
{
	Botan::secure_vector<uint8_t> result;
	std::vector<uint8_t> buf(2048);

	std::ifstream in(file, std::ios::binary);
	if (!in.is_open())
	{
		return result;
	}

	try {
		const auto hash = Botan::HashFunction::create_or_throw(algo);

		while (in.good()) {

			in.read(reinterpret_cast<char*>(buf.data()), buf.size());

			size_t readcount = in.gcount();

			if (readcount > 0)
			{
				hash->update(buf.data(), readcount);
			}
		}

		result = hash->final();
	}
	catch (...) {

		in.close();
		return Botan::secure_vector<uint8_t>();
	}

	in.close();

	return result;
}

unsigned int CryptoManager::deriveKeyFromPassword(
	const std::string& password,
	KdfParameters& param,
	KeyParameters& keydata,
	const std::bitset<6>& flag,
	const std::string& kdf,
	const std::string& keyfile
)
{
	try {
		Botan::AutoSeeded_RNG rng;

		keydata.key = Botan::secure_vector<uint8_t>(KEY_SIZE);
		auto pwd_fam = Botan::PasswordHashFamily::create_or_throw(kdf);

		if (flag.test(ENCRYPT) && !flag.test(KEYFILE))
		{
			keydata.salt = Botan::secure_vector<uint8_t>(SALT_SIZE);
			rng.randomize(&keydata.salt[0], SALT_SIZE);
		}

		if ((flag.test(ENCRYPT) || flag.test(DECRYPT)) && flag.test(KEYFILE))
		{
			if (keyfile.empty()) 
				return ERROR_KEYFILE_MISSING;

			keydata.salt = getHashFile(keyfile, "Keccak-1600(512)");

			if(keydata.salt.empty())
				return ERROR_DERIVE_KEY;
		}

		if (param.kdf_strength < 0 || param.kdf_strength > 2) 
			return ERROR_KDF_STRENGTH;

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

		auto pwdhash = pwd_fam->from_params(param.memory, param.time, param.parallelism);

		pwdhash->hash(keydata.key, password, keydata.salt);
	}
	catch (...) {

		return ERROR_DERIVE_KEY;
	}

	return 0;
}

size_t CryptoManager::encryptFile(
	const std::string& inputFilename,
	const std::string& outputFilename,
	const KeyParameters& keyparams,
	const std::string& selectedCipher,
	const std::bitset<6>& flag,
	const OptionalFetterHeader* header
)
{
	std::ifstream in(inputFilename, std::ios::in | std::ios::binary);
	if (!in.is_open()) {
		return ERROR_OPEN_FILE;
	}

	std::ofstream out(outputFilename, std::ios::out | std::ios::binary);
	if (!out.is_open()) {
		in.close();
		return ERROR_OPEN_FILE;
	}

	std::vector<uint8_t> buffer;

	try {

	Botan::AutoSeeded_RNG rng;
	std::unique_ptr<Botan::Pipe> pipe;

	Botan::SymmetricKey key(keyparams.key.data(), keyparams.key.size());
	Botan::InitializationVector iv(rng, IV_SIZE);
	Botan::secure_vector<uint8_t> iv_bits = iv.bits_of();

	std::copy(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>(), std::back_inserter(buffer));
	in.close();

	if (flag.test(HEADER) && header != nullptr) {

		out.write(reinterpret_cast<const char*>(header), sizeof(OptionalFetterHeader));
	}

	if (flag.test(KEYFILE)) {

		Botan::secure_vector<uint8_t> salt = Botan::secure_vector<uint8_t>(SALT_SIZE);
		rng.randomize(&salt[0], SALT_SIZE);

		out.write((const char*)iv_bits.data(), iv_bits.size());
		out.write((const char*)salt.data(), salt.size());
	}
	else {
		out.write((const char*)iv_bits.data(), iv_bits.size());
		out.write((const char*)keyparams.salt.data(), keyparams.salt.size());
	}

	if (flag.test(COMPRESS)) {
		pipe = std::make_unique<Botan::Pipe>(
			new Botan::Compression_Filter("bzip2", 9),
			Botan::get_cipher(selectedCipher, key, iv, Botan::Cipher_Dir::Encryption),
			new Botan::DataSink_Stream(out));
	} else {
			pipe = std::make_unique<Botan::Pipe>(Botan::get_cipher(selectedCipher, key, iv, Botan::Cipher_Dir::Encryption), new Botan::DataSink_Stream(out));
	}

	pipe->process_msg(buffer.data(), buffer.size());
	}
	catch (...)
	{
		std::vector<uint8_t>().swap(buffer);
		out.close();

		return ERROR_ENCRYPT;
	}

	std::vector<uint8_t>().swap(buffer);
	out.close();

	return ERROR_OK;
}

size_t CryptoManager::decryptFile(
	const std::string& inputFilename,
	const std::string& outputFilename,
	const KeyParameters& keyparams,
	const std::string& selectedCipher,
	const std::bitset<6>& flag,
	bool& stop,
	const OptionalFetterHeader* header
) {
	std::vector<uint8_t> buffer;

	std::ifstream in(inputFilename, std::ios::in | std::ios::binary);
	if (!in.is_open()) {
		return ERROR_OPEN_FILE;
	}

	std::ofstream out(outputFilename, std::ios::out | std::ios::binary);
	if (!out.is_open()) {
		in.close();
		return ERROR_OPEN_FILE;
	}

	Botan::SymmetricKey key(keyparams.key.data(), keyparams.key.size());
	Botan::InitializationVector iv(keyparams.iv.data(), keyparams.iv.size());
	std::unique_ptr<Botan::Pipe> pipe;

	if (flag.test(HEADER)) {

		in.seekg(IV_SIZE + SALT_SIZE + HEADER_SIZE);
		std::copy(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>(), std::back_inserter(buffer));
		in.close();
	}
	else {

		in.seekg(IV_SIZE + SALT_SIZE);
		std::copy(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>(), std::back_inserter(buffer));
		in.close();
	}

	if (!flag.test(HEADER)) {
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
				catch (Botan::Invalid_State& e) {

					std::vector<uint8_t>().swap(buffer);
					out.close();

					return ERROR_DECRYPT;
				}
				catch (...) {

					std::vector<uint8_t>().swap(buffer);
					out.close();

					return ERROR_DECRYPT;
				}
			}
		}
	}
	else {
		try {
			if (flag.test(COMPRESS)) {

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

		}
		catch (Botan::Invalid_Authentication_Tag) {

			std::vector<uint8_t>().swap(buffer);
			out.close();

			return ERROR_DECRYPT;
		}
		catch (...) {

			std::vector<uint8_t>().swap(buffer);
			out.close();

			return ERROR_DECRYPT;
		}
	}

	std::vector<uint8_t>().swap(buffer);
	out.close();

	return ERROR_OK;
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

	keyparams.iv = iv;
	keyparams.salt = salt;

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