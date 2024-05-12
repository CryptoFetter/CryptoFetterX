#include "Crypto.h"

Botan::secure_vector<uint8_t> getHashFile(std::string file, std::string algo)
{
	const auto hash = Botan::HashFunction::create_or_throw(algo);
	Botan::secure_vector<uint8_t> result;
	std::vector<uint8_t> buf(2048);

	std::ifstream in(file, std::ios::binary);
	if (!in.is_open())
	{
		return result;
	}

	while (in.good()) {

		in.read(reinterpret_cast<char*>(buf.data()), buf.size());
		size_t readcount = in.gcount();

		hash->update(buf.data(), readcount);
	}
	in.close();

	result = hash->final();

	return result;
}

void derive_key_from_password(const std::string& password, KdfParameters& param, KeyParameters& keydata, std::bitset<4> &flag, const std::string& kdf, const std::string& keyfile)
{
	keydata.key = Botan::secure_vector<uint8_t>(KEY_SIZE);

	if (flag.test(ENCRYPT) && !flag.test(KEYFILE))	// encrypt
	{
		keydata.salt = Botan::secure_vector<uint8_t>(SALT_SIZE);
		Botan::system_rng().randomize(keydata.salt);
	}

	if ((flag.test(ENCRYPT) || flag.test(DECRYPT)) && flag.test(KEYFILE))
	{
		if (keyfile.empty()) return;

		keydata.salt = getHashFile(keyfile, "Keccak-1600(512)");
	}
	
	auto pwd_fam = Botan::PasswordHashFamily::create_or_throw(kdf);

	if (param.kdf_strength < 0 || param.kdf_strength > 2) return;

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

void encryptFile(const std::string& inputFilename, const std::string& outputFilename, const KeyParameters& keyparams, wxGauge* gauge, const std::string &selectedCipher, std::bitset<3>& flag, EncryptFileHeader* header)
{
	Botan::AutoSeeded_RNG rng;
	std::unique_ptr<Botan::Pipe> pipe;

	std::ifstream in(inputFilename, std::ios::in | std::ios::binary);
	std::ofstream out(outputFilename, std::ios::out | std::ios::binary);

	gauge->SetValue(0);

	Botan::SymmetricKey key(keyparams.key.data(), keyparams.key.size());
	Botan::InitializationVector iv(rng, IV_SIZE);
	Botan::secure_vector<uint8_t> iv_bits = iv.bits_of();

	in.seekg(0, std::ios::end);
	size_t totalFileSize = in.tellg();

	in.seekg(0);

	if (flag.test(HEADER) && header != nullptr) {

		out.write(reinterpret_cast<const char*>(header), sizeof(EncryptFileHeader));

	}

	out.write((const char*)iv_bits.data(), iv_bits.size());
	out.write((const char*)keyparams.salt.data(), keyparams.salt.size());

	std::vector<uint8_t> buffer(totalFileSize + (IV_SIZE + SALT_SIZE + NONCE));

	auto cipher = Botan::get_cipher(selectedCipher, key, iv, Botan::Cipher_Dir::Encryption);

	try {
		size_t totalBytesWritten = 0;

		while (!in.eof())
		{

			if (flag.test(COMPRESS)) {
				pipe = std::make_unique<Botan::Pipe>(new Botan::Chain(
					new Botan::Compression_Filter("bzip2", 9),
					cipher,
					new Botan::DataSink_Stream(out)));
			}
			else {
				pipe = std::make_unique<Botan::Pipe>(cipher, new Botan::DataSink_Stream(out));
			}

			iv = Botan::InitializationVector(rng, IV_SIZE);

			in.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
			auto bytesRead = in.gcount();
			pipe->process_msg(buffer.data(), in.gcount());

			totalBytesWritten += bytesRead;
			
			if (gauge != nullptr) {

				int x = 0;

				x = (totalBytesWritten * 100) / (totalFileSize - 80);
				gauge->SetValue((totalBytesWritten * 100) / (totalFileSize));
			}
		}
	} catch (const std::exception& e)
	{
		MessageBoxA(nullptr, e.what(), "Encrypt", MB_OK | MB_ICONERROR);
	}

	in.close();
	out.close();
}

void decryptFile(const std::string& inputFilename, const std::string& outputFilename, const KeyParameters& keyparams, wxGauge* gauge, const std::string& selectedCipher, std::bitset<3>& flag, bool &stop, EncryptFileHeader* header) {
	Botan::AutoSeeded_RNG rng;
	
	std::ifstream in(inputFilename, std::ios::binary);
	if (!in.is_open()) {
		return;
	}

	std::ofstream out(outputFilename, std::ios::binary);
	if (!out.is_open()) {
		in.close();
		return;
	}

	gauge->SetValue(0);

	Botan::SymmetricKey key(keyparams.key.data(), keyparams.key.size());

	Botan::InitializationVector iv(keyparams.iv.data(), keyparams.iv.size());

	in.seekg(0, std::ios::end);
	size_t totalFileSize = in.tellg();

	size_t totalBytesRead = 0;

	std::vector<uint8_t> buffer;

	if (flag.test(DENIABILITY)) {

		in.seekg(IV_SIZE + SALT_SIZE);
		buffer.resize(totalFileSize - (IV_SIZE + SALT_SIZE));
	}
	else {

		in.seekg(IV_SIZE + SALT_SIZE + HEADER_SIZE);
		buffer.resize(totalFileSize - (IV_SIZE + SALT_SIZE + HEADER_SIZE));

	}

	std::unique_ptr<Botan::Pipe> pipe;

	if (flag.test(DENIABILITY)) {

		for (const auto& algorithm : algorithms) {
			try {
				if (flag.test(COMPRESS)) {

					pipe = std::make_unique<Botan::Pipe>(new Botan::Chain(
						Botan::get_cipher(algorithm, key, iv, Botan::Cipher_Dir::Decryption),
						new Botan::Decompression_Filter("bzip2", 9),
						new Botan::DataSink_Stream(out)
					));
				}
				else {
					pipe = std::make_unique<Botan::Pipe>(Botan::get_cipher(algorithm, key, iv, Botan::Cipher_Dir::Decryption), new Botan::DataSink_Stream(out));
				}

				while (in.good()) {
					in.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

					auto bytesRead = in.gcount();

					pipe->process_msg(buffer.data(), in.gcount());

					totalBytesRead += bytesRead;

					if (gauge != nullptr) {

						int x = 0;

						x = (totalBytesRead * 100) / (totalFileSize - 80);
						gauge->SetValue((totalBytesRead * 100) / (totalFileSize - 80));
					}
				}

				stop = true;

				std::cout << "File decrypted successfully using " << algorithm << std::endl;

				return;
			}
			catch (const Botan::Invalid_Authentication_Tag& e) {

				std::cerr << "Failed to authenticate the ciphertext with algorithm " << algorithm << ": " << e.what() << std::endl;

				out.clear();
				out.seekp(0);

				in.seekg(IV_SIZE + SALT_SIZE);
			}
			catch (const std::exception& e) {

				std::cerr << "An error occurred while decrypting with algorithm " << algorithm << ": " << e.what() << std::endl;

				out.clear();
				out.seekp(0);

				in.seekg(IV_SIZE + SALT_SIZE);
			}
		}
	}
	else {
		try{

		if (flag.test(COMPRESS)) {

			pipe = std::make_unique<Botan::Pipe>(new Botan::Chain(
				Botan::get_cipher(selectedCipher, key, iv, Botan::Cipher_Dir::Decryption),
				new Botan::Decompression_Filter("bzip2", 9),
				new Botan::DataSink_Stream(out)
			));
		}
		else {
			pipe = std::make_unique<Botan::Pipe>(Botan::get_cipher(selectedCipher, key, iv, Botan::Cipher_Dir::Decryption), new Botan::DataSink_Stream(out));
		}

		while (in.good()) {
			in.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

			auto bytesRead = in.gcount();

			pipe->process_msg(buffer.data(), in.gcount());

			totalBytesRead += bytesRead;

			if (gauge != nullptr) {

				int x = 0;

				x = (totalBytesRead * 100) / (totalFileSize - 185);
				gauge->SetValue((totalBytesRead * 100) / (totalFileSize - 185));
			}
		}
	}
	catch (const Botan::Invalid_Authentication_Tag& e) {

		MessageBoxA(nullptr, e.what(), "Decrypt", MB_OK | MB_ICONERROR);

		in.close();
		out.close();
		}
	catch (const std::exception& e) {

		MessageBoxA(nullptr, e.what(), "Decrypt", MB_OK | MB_ICONERROR);

		in.close();
		out.close();
	}
	}

	in.close();
	out.close();
}

void getKeyParameters(const std::string& inputFilename, KeyParameters& keyparams, EncryptFileHeader* header)
{
	std::ifstream in(inputFilename, std::ios::in | std::ios::binary);

	Botan::secure_vector<uint8_t> iv(IV_SIZE);
	Botan::secure_vector<uint8_t> salt(SALT_SIZE);

	if (header)
	{
		in.read(reinterpret_cast<char*>(header), sizeof(EncryptFileHeader));
	}

	in.read(reinterpret_cast<char*>(iv.data()), IV_SIZE);
	in.read(reinterpret_cast<char*>(salt.data()), SALT_SIZE);

	keyparams.iv = iv;
	keyparams.salt = salt;

	in.seekg(0);
	in.close();

}

void writeHeaderToFile(const EncryptFileHeader& header, const std::string& fileName) {
	std::ofstream file(fileName, std::ios::binary);
	if (file.is_open()) {
		file.write(reinterpret_cast<const char*>(&header), sizeof(EncryptFileHeader));

		file.close();
		std::cout << "Header has been written to file." << std::endl;
	}
	else {
		std::cerr << "Error opening file for writing." << std::endl;
	}
}

EncryptFileHeader createEncryptFileHeader(
	uint8_t version, 
	uint8_t encrID, 
	uint8_t kdfID, 
	uint8_t kdfStrength, 
	uint8_t compressFlag, 
	uint8_t keyfileFlag
) {
	EncryptFileHeader header;

	header.version = version;
	header.encryptionAlgorithmID = encrID;
	header.kdfAlgorithmID = kdfID;
	header.kdfStrength = kdfStrength;
	header.compressFlag = compressFlag;
	header.keyfileFlag = keyfileFlag;

	for (int i = 0; i < 99; ++i) {
		header.reserved[i] = 0;
	}

	return header;
}

double calculateEntropy(const std::string& password) {

	const int specialCharSize = 15;
	int charsetSize = 0;
	bool hasLowerCase = false, hasUpperCase = false, hasDigit = false, hasSpecialChar = false;

	for (char ch : password) {
		if (islower(ch)) hasLowerCase = true;
		else if (isupper(ch)) hasUpperCase = true;
		else if (isdigit(ch)) hasDigit = true;
		else hasSpecialChar = true;

		charsetSize = 0
			+ (hasLowerCase ? 26 : 0)
			+ (hasUpperCase ? 26 : 0)
			+ (hasDigit ? 10 : 0)
			+ (hasSpecialChar ? specialCharSize : 0);

		int effectiveCharsetSize = charsetSize;
		if (effectiveCharsetSize == 0) effectiveCharsetSize = 1;

		return password.length() * std::log2(effectiveCharsetSize);
	}
}
