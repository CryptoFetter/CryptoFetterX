#include "Crypto.h"

#include <wx/wx.h>

Botan::secure_vector<uint8_t> CryptoManager::getHashFile(
	std::string file,
	std::string algo
)
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

unsigned int CryptoManager::deriveKeyFromPassword(
	const std::string& password,
	KdfParameters& param,
	KeyParameters& keydata,
	std::bitset<4>& flag,
	const std::string& kdf,
	const std::string& keyfile
)
{
	keydata.key = Botan::secure_vector<uint8_t>(KEY_SIZE);

	if (flag.test(ENCRYPT) && !flag.test(KEYFILE))
	{
		keydata.salt = Botan::secure_vector<uint8_t>(SALT_SIZE);
		Botan::system_rng().randomize(keydata.salt);
	}

	if ((flag.test(ENCRYPT) || flag.test(DECRYPT)) && flag.test(KEYFILE))
	{
		if (keyfile.empty()) return ERROR_KEYFILE_MISSING;

		keydata.salt = getHashFile(keyfile, "Keccak-1600(512)");
	}

	auto pwd_fam = Botan::PasswordHashFamily::create_or_throw(kdf);

	if (param.kdf_strength < 0 || param.kdf_strength > 2) return ERROR_KDF_STRENGTH;

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

	return 0;
}

void CryptoManager::encryptFile(
	const std::string& inputFilename,
	const std::string& outputFilename,
	const KeyParameters& keyparams,
	const std::string& selectedCipher,
	std::bitset<3>& flag,
	const OptionalFetterHeader* header
)
{
	Botan::AutoSeeded_RNG rng;
	std::unique_ptr<Botan::Pipe> pipe;

	std::ifstream in(inputFilename, std::ios::in | std::ios::binary);
	std::ofstream out(outputFilename, std::ios::out | std::ios::binary);

	Botan::SymmetricKey key(keyparams.key.data(), keyparams.key.size());
	Botan::InitializationVector iv(rng, IV_SIZE);
	Botan::secure_vector<uint8_t> iv_bits = iv.bits_of();

	in.seekg(0, std::ios::end);
	size_t totalFileSize = in.tellg();

	in.seekg(0);

	if (flag.test(HEADER) && header != nullptr) {

		out.write(reinterpret_cast<const char*>(header), sizeof(OptionalFetterHeader));

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
		}
	}
	catch (const std::exception& e)
	{

	}

	in.close();
	out.close();
}

void CryptoManager::decryptFile(
	const std::string& inputFilename,
	const std::string& outputFilename,
	const KeyParameters& keyparams,
	const std::string& selectedCipher,
	std::bitset<3>& flag,
	bool& stop,
	OptionalFetterHeader* header
) {
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

	Botan::SymmetricKey key(keyparams.key.data(), keyparams.key.size());

	Botan::InitializationVector iv(keyparams.iv.data(), keyparams.iv.size());

	in.seekg(0, std::ios::end);
	size_t totalFileSize = in.tellg();

	size_t totalBytesRead = 0;

	std::vector<uint8_t> buffer;

	if (flag.test(HEADER)) {

		in.seekg(IV_SIZE + SALT_SIZE + HEADER_SIZE);
		buffer.resize(totalFileSize - (IV_SIZE + SALT_SIZE + HEADER_SIZE));
	}
	else {

		in.seekg(IV_SIZE + SALT_SIZE);
		buffer.resize(totalFileSize - (IV_SIZE + SALT_SIZE));
	}

	bool x = true;

	int y = 1;

	std::unique_ptr<Botan::Pipe> pipe;

	if (!flag.test(HEADER)) {

		for (const auto& algorithm : algorithms) {
			for (int attempt = 0; attempt < 2; ++attempt) {

				bool useCompression = (attempt == 0);

				try {

					if (useCompression) {

						pipe.reset();
						pipe = std::make_unique<Botan::Pipe>(new Botan::Chain(
							Botan::get_cipher(algorithm, key, iv, Botan::Cipher_Dir::Decryption),
							new Botan::Decompression_Filter("bzip2", 9),
							new Botan::DataSink_Stream(out)
						));
						compressFlag = true;
					}
					else {
						pipe.reset();
						pipe = std::make_unique<Botan::Pipe>(Botan::get_cipher(algorithm, key, iv, Botan::Cipher_Dir::Decryption), new Botan::DataSink_Stream(out));
						compressFlag = false;
					}

					while (in.good()) {
						in.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

						auto bytesRead = in.gcount();

						pipe->process_msg(buffer.data(), in.gcount());

						totalBytesRead += bytesRead;
					}

					stop = true;
					cipherAlgo = algorithm;

					return;
				}
				catch (const Botan::Invalid_Authentication_Tag& e) {
					out.clear();
					out.seekp(0);
					in.seekg(IV_SIZE + SALT_SIZE);
				}
				catch (const Botan::Compression_Error& e) {
					out.clear();
					out.seekp(0);
					in.seekg(IV_SIZE + SALT_SIZE);
				}
				catch (const std::exception& e) {

					std::string errorText = e.what();

					wxMessageDialog dialog(NULL, wxString::FromUTF8(errorText.c_str()), "Error", wxOK | wxICON_ERROR);

					out.clear();
					out.seekp(0);
					in.seekg(IV_SIZE + SALT_SIZE);
				}
			}
		}

	}
	else {
		try {
			if (flag.test(COMPRESS)) {

				pipe.reset();
				pipe = std::make_unique<Botan::Pipe>(new Botan::Chain(
					Botan::get_cipher(selectedCipher, key, iv, Botan::Cipher_Dir::Decryption),
					new Botan::Decompression_Filter("bzip2", 9),
					new Botan::DataSink_Stream(out)
				));
			}
			else {

				pipe.reset();
				pipe = std::make_unique<Botan::Pipe>(Botan::get_cipher(selectedCipher, key, iv, Botan::Cipher_Dir::Decryption), new Botan::DataSink_Stream(out));
			}

			while (in.good()) {
				in.read(reinterpret_cast<char*>(buffer.data()), buffer.size());

				auto bytesRead = in.gcount();

				pipe->process_msg(buffer.data(), in.gcount());

				totalBytesRead += bytesRead;
			}
		}
		catch (const Botan::Invalid_Authentication_Tag& e) {

			in.close();
			out.close();
		}
		catch (const std::exception& e) {

			in.close();
			out.close();
		}
	}

	in.close();
	out.close();
}

bool CryptoManager::getKeyParameters(
	const std::string& inputFilename,
	KeyParameters& keyparams,
	OptionalFetterHeader* header
)
{
	std::ifstream in(inputFilename, std::ios::in | std::ios::binary);

	Botan::secure_vector<uint8_t> iv(IV_SIZE);
	Botan::secure_vector<uint8_t> salt(SALT_SIZE);

	in.seekg(6, std::ios::beg);

	char byte7, byte8, byte9;
	in.read(&byte7, 1);
	in.read(&byte8, 1);
	in.read(&byte9, 1);

	in.seekg(0, std::ios::beg);

	bool result = (byte7 == 0x07 && byte8 == 0x07 && byte9 == 0x07);

	if (result)
	{
		in.read(reinterpret_cast<char*>(header), sizeof(OptionalFetterHeader));
	}

	in.read(reinterpret_cast<char*>(iv.data()), IV_SIZE);
	in.read(reinterpret_cast<char*>(salt.data()), SALT_SIZE);

	keyparams.iv = iv;
	keyparams.salt = salt;

	in.seekg(0);
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

double CryptoManager::calculateEntropy(
	const std::string& password
) {
	const int specialCharSize = 15;
	int charsetSize = 0;
	bool hasLowerCase = false, hasUpperCase = false, hasDigit = false, hasSpecialChar = false;

	for (char ch : password) {
		if (islower(ch)) hasLowerCase = true;
		else if (isupper(ch)) hasUpperCase = true;
		else if (isdigit(ch)) hasDigit = true;
		else hasSpecialChar = true;
	}

	charsetSize = 0
		+ (hasLowerCase ? 26 : 0)
		+ (hasUpperCase ? 26 : 0)
		+ (hasDigit ? 10 : 0)
		+ (hasSpecialChar ? specialCharSize : 0);

	int effectiveCharsetSize = charsetSize;
	if (effectiveCharsetSize == 0) effectiveCharsetSize = 1;

	return password.length() * std::log2(effectiveCharsetSize);
}