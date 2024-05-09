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

void derive_key_from_password(const std::string& password, KdfParameters& param, KeyParameters& keydata, std::bitset<3> &flag, const std::string& kdf, const std::string& keyfile)
{
	keydata.key = Botan::secure_vector<uint8_t>(KEY_SIZE);

	if (flag.test(ENCRYPT) && !flag.test(KEYFILE))
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

	if (param.kdf_strenth >= 0 && param.kdf_strenth <= 2) return;

	if (kdf == "Argon2id") {
		switch (param.kdf_strenth) {
		case 0: param = { 0, 131070, 12, 4 }; break;
		case 1: param = { 1, 524280, 22, 4 }; break;
		case 2: param = { 2, 2097120, 32, 4 }; break;
		}
	}
	else if (kdf == "Scrypt") {
		switch (param.kdf_strenth) {
		case 0: param = { 0, 131072, 8, 1 }; break;
		case 1: param = { 1, 524288, 8, 3 }; break;
		case 2: param = { 2, 2097152, 8, 4 }; break;
		}
	}

	auto pwdhash = pwd_fam->from_params(param.memory, param.time, param.parallelism);

	pwdhash->hash(keydata.key, password, keydata.salt);
}

void encryptFile(const std::string& inputFilename, const std::string& outputFilename, const KeyParameters& keyparams, wxGauge* gauge, const std::string &selectedCipher)
{
	Botan::AutoSeeded_RNG rng;

	std::ifstream in(inputFilename, std::ios::in | std::ios::binary);
	std::ofstream out(outputFilename, std::ios::out | std::ios::binary);

	gauge->SetValue(0);

	Botan::SymmetricKey key(keyparams.key.data(), keyparams.key.size());
	Botan::InitializationVector iv(rng, IV_SIZE);
	Botan::secure_vector<uint8_t> iv1 = iv.bits_of();

	in.seekg(0, std::ios::end);
	size_t totalFileSize = in.tellg();

	in.seekg(0);

	out.write((const char*)iv1.data(), iv1.size());
	out.write((const char*)keyparams.salt.data(), keyparams.salt.size());

	std::vector<uint8_t> buffer(totalFileSize + (IV_SIZE + SALT_SIZE + NONCE));

	try {
		size_t totalBytesWritten = 0;

		while (!in.eof())
		{
			Botan::Pipe pipe(Botan::get_cipher(selectedCipher, key, iv, Botan::Cipher_Dir::Encryption), new Botan::DataSink_Stream(out));

			iv = Botan::InitializationVector(rng, IV_SIZE);

			in.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
			auto bytesRead = in.gcount();
			pipe.process_msg(buffer.data(), in.gcount());

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

void decryptFile(const std::string& inputFilename, const std::string& outputFilename, const KeyParameters& keyparams, wxGauge* gauge, const std::string& selectedCipher, bool deniabilityFlag, bool &stop) {
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

	in.seekg(IV_SIZE + SALT_SIZE);

	size_t totalBytesRead = 0;

	std::vector<uint8_t> buffer(totalFileSize - (IV_SIZE + SALT_SIZE));

	if (deniabilityFlag) {

		for (const auto& algorithm : algorithms) {
			try {

				Botan::Pipe pipe(Botan::get_cipher(algorithm, key, iv, Botan::Cipher_Dir::Decryption), new Botan::DataSink_Stream(out));

				while (in.good()) {
					in.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

					auto bytesRead = in.gcount();

					pipe.process_msg(buffer.data(), in.gcount());

					totalBytesRead += bytesRead;

					if (gauge != nullptr) {

						int x = 0;

						x = (totalBytesRead * 100) / (totalFileSize - 80);
						gauge->SetValue((totalBytesRead * 100) / (totalFileSize - 80));
					}
				}

				stop = true;

				return;
			}
			catch (const Botan::Invalid_Authentication_Tag& e) {

				out.clear();
				out.seekp(0);

				in.seekg(IV_SIZE + SALT_SIZE);
			}
			catch (const std::exception& e) {

				out.clear();
				out.seekp(0);

				in.seekg(IV_SIZE + SALT_SIZE);
			}
		}
	}
	else {	
		try{
		Botan::Pipe pipe(Botan::get_cipher(selectedCipher, key, iv, Botan::Cipher_Dir::Decryption), new Botan::DataSink_Stream(out));

		while (in.good()) {
			in.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

			auto bytesRead = in.gcount();

			pipe.process_msg(buffer.data(), in.gcount());

			totalBytesRead += bytesRead;

			if (gauge != nullptr) {

				int x = 0;

				x = (totalBytesRead * 100) / (totalFileSize - 80);
				gauge->SetValue((totalBytesRead * 100) / (totalFileSize - 80));
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

	std::cout << "File is decrypted successfully" << std::endl;
}

void getKeyParameters(const std::string& inputFilename, KeyParameters& keyparams)
{
	std::ifstream in(inputFilename, std::ios::in | std::ios::binary);

	Botan::secure_vector<uint8_t> iv(IV_SIZE);
	Botan::secure_vector<uint8_t> salt(SALT_SIZE);

	in.read(reinterpret_cast<char*>(iv.data()), IV_SIZE);
	in.read(reinterpret_cast<char*>(salt.data()), SALT_SIZE);

	keyparams.iv = iv;
	keyparams.salt = salt;

	in.seekg(0);
	in.close();
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
