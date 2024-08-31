#include "EncryptFrame.h"
#include "Crypto.h"

#include "EntropyDialog.h"

namespace fs = std::filesystem;

EncryptFrame::EncryptFrame(const wxString& title) :wxFrame(nullptr, wxID_ANY, title)
{
	wxNotebook* notebook = new wxNotebook(this, wxID_ANY);

	wxPanel* crypto = new wxPanel(notebook);
	wxPanel* hasher = new wxPanel(notebook);

	notebook->AddPage(crypto, "File encryption");
	notebook->AddPage(hasher, "Hasher");

	// StaticBox "Enter password"
	wxStaticBox* password_box = new wxStaticBox(crypto, wxID_ANY, "Enter password", wxPoint(520, 10), wxSize(270, 240));

	wxStaticText* confirm_text = new wxStaticText(crypto, wxID_ANY, "Confirm password:", wxPoint(530, 95), wxSize(250, 25));
	wxStaticText* quality_text = new wxStaticText(crypto, wxID_ANY, "Password quality:", wxPoint(530, 200), wxSize(250, 25));

	passText = new wxTextCtrl(crypto, wxID_ANY, "", wxPoint(530, 60), wxSize(250, 25), wxTE_PASSWORD);
	confPassText = new wxTextCtrl(crypto, wxID_ANY, "", wxPoint(530, 120), wxSize(250, 25), wxTE_PASSWORD);

	keyfileStaticText = new wxStaticText(crypto, wxID_ANY, "", wxPoint(610, 165), wxSize(170, 25), wxST_NO_AUTORESIZE);

#ifdef _WIN32
	hidePassCheckBox = new wxCheckBox(crypto, wxID_ANY, "Unhide password", wxPoint(530, 35));
	hidePassCheckBox->Bind(wxEVT_CHECKBOX, &EncryptFrame::OnHidePassBox, this);
#endif

	key_file = new wxButton(crypto, wxID_ANY, "KeyFile", wxPoint(530, 160), wxSize(70, 25));

	hWndPassword = static_cast<HWND>(passText->GetHandle());
	SendMessageW(hWndPassword, EM_SETPASSWORDCHAR, static_cast<WPARAM>('*'), 0);
	passText->Refresh();

	hWndConfirmPassword = static_cast<HWND>(confPassText->GetHandle());
	SendMessageW(hWndConfirmPassword, EM_SETPASSWORDCHAR, static_cast<WPARAM>('*'), 0);
	confPassText->Refresh();


	passText->Bind(wxEVT_TEXT, &EncryptFrame::OnEnterPass, this);
	confPassText->Bind(wxEVT_TEXT, &EncryptFrame::OnEnterPass, this);
	key_file->Bind(wxEVT_BUTTON, &EncryptFrame::OnOpenKeyFile, this);

	key_file->Enable(false);
	keyfileStaticText->Enable(false);

	// StaticBox "Encrypt settings"
	wxStaticBox* settings_box = new wxStaticBox(crypto, wxID_ANY, "Encrypt settings", wxPoint(520, 260), wxSize(270, 220));

	wxStaticText* cipher_text		= new wxStaticText(crypto, wxID_ANY, "Cipher:", wxPoint(530, 290), wxSize(120, 25));
	wxStaticText* derive_text		= new wxStaticText(crypto, wxID_ANY, "Key derive function:", wxPoint(530, 330), wxSize(120, 25));
	wxStaticText* derive_set_text	= new wxStaticText(crypto, wxID_ANY, "Key derive strong:", wxPoint(530, 370), wxSize(120, 25));

	compress_flag	= new wxCheckBox(crypto, wxID_ANY, "Compress", wxPoint(530, 435));
	delete_flag		= new wxCheckBox(crypto, wxID_ANY, "Delete original", wxPoint(530, 455));
	keyfile_flag	= new wxCheckBox(crypto, wxID_ANY, "Keyfile", wxPoint(670, 415));
	hard_rng_flag	= new wxCheckBox(crypto, wxID_ANY, "Hard PRNG", wxPoint(670, 435));
	header_flag		= new wxCheckBox(crypto, wxID_ANY, "Header enabled", wxPoint(530, 415));

	compress_flag->SetToolTip(new wxToolTip("You should always compress before you encrypt, because encryption seeks to hide the redundancy that compression is supposed to try to find and remove"));
	header_flag->SetToolTip(new wxToolTip("Adding a header greatly speeds up the decryption speed, but significantly weakens the defense because the attacker becomes aware of the encryption algorithms used"));

	progress_pass = new wxGauge(crypto, wxID_ANY, 100, wxPoint(530, 225), wxSize(250, 15));

	compress_flag->SetValue(true);

	compress_flag->Bind(wxEVT_CHECKBOX, &EncryptFrame::OnCompressCheckBoxChanged, this);
	keyfile_flag->Bind(wxEVT_CHECKBOX, &EncryptFrame::OnKeyfileBoxChanged, this);
	header_flag->Bind(wxEVT_CHECKBOX, &EncryptFrame::OnHeaderBoxChanged, this);

	// StaticBox "Status"
	wxStaticBox* status_box = new wxStaticBox(crypto, wxID_ANY, "Status", wxPoint(0, 200), wxSize(515, 200));

	textCipher		= new wxStaticText(crypto, wxID_ANY, wxEmptyString, wxPoint(15, 215), wxSize(495, 20), wxST_NO_AUTORESIZE);
	textKdf			= new wxStaticText(crypto, wxID_ANY, wxEmptyString, wxPoint(15, 235), wxSize(495, 20), wxST_NO_AUTORESIZE);
	textKdfStrength = new wxStaticText(crypto, wxID_ANY, wxEmptyString, wxPoint(15, 255), wxSize(495, 20), wxST_NO_AUTORESIZE);
	textHeader		= new wxStaticText(crypto, wxID_ANY, wxEmptyString, wxPoint(15, 275), wxSize(495, 20), wxST_NO_AUTORESIZE);
	textCompress	= new wxStaticText(crypto, wxID_ANY, wxEmptyString, wxPoint(15, 295), wxSize(495, 20), wxST_NO_AUTORESIZE);
	textKeyfile		= new wxStaticText(crypto, wxID_ANY, wxEmptyString, wxPoint(15, 315), wxSize(495, 20), wxST_NO_AUTORESIZE);
	textIV			= new wxStaticText(crypto, wxID_ANY, wxEmptyString, wxPoint(15, 335), wxSize(495, 20), wxST_NO_AUTORESIZE);
	textSalt		= new wxStaticText(crypto, wxID_ANY, wxEmptyString, wxPoint(15, 355), wxSize(495, 20), wxST_NO_AUTORESIZE);
	textKey			= new wxStaticText(crypto, wxID_ANY, wxEmptyString, wxPoint(15, 375), wxSize(495, 20), wxST_NO_AUTORESIZE);

	wxArrayString selectCipher;

	for (const auto& algorithm : cipherAlgorithms) {
		selectCipher.Add(algorithm.second);
	}

	cipher_choice = new wxChoice(crypto, wxID_ANY, wxPoint(655, 285), wxSize(125, 30), selectCipher);
	cipher_choice->Select(0);

	wxArrayString selectKdf;

	for (const auto& algorithm : kdfAlgorithms) {
		selectKdf.Add(algorithm.second);
	}

	kdf_choice = new wxChoice(crypto, wxID_ANY, wxPoint(655, 325), wxSize(125, 30), selectKdf);
	kdf_choice->Select(0);

	kdf_slider = new wxSlider(crypto, wxID_ANY, 0, 0, 2, wxPoint(655, 365), wxSize(125, 30));

	// Other
	encryptButton = new wxButton(crypto, wxID_ANY, "Encrypt", wxPoint(0, 405), wxSize(170, 45));
	encryptButton->Bind(wxEVT_BUTTON, &EncryptFrame::OnEncryptFile, this);

	decryptButton = new wxButton(crypto, wxID_ANY, "Decrypt", wxPoint(345, 405), wxSize(170, 45));
	decryptButton->Bind(wxEVT_BUTTON, &EncryptFrame::OnDecryptFile, this);

	wxButton* crypt_file = new wxButton(crypto, wxID_ANY, "Select File", wxPoint(0, 160), wxSize(115, 35));
	crypt_file->Bind(wxEVT_BUTTON, &EncryptFrame::OnOpenCryptFile, this);

	progress_crypt = new wxGauge(crypto, wxID_ANY, 100, wxPoint(0, 455), wxSize(515, 25));

	wxButton* output_file = new wxButton(crypto, wxID_ANY, "Output folder", wxPoint(135, 160), wxSize(115, 35));
	output_file->Bind(wxEVT_BUTTON, &EncryptFrame::OnSaveOutputFolder, this);

	fileListToCrypt = new wxListCtrl(crypto, wxID_ANY, wxPoint(0, 15), wxSize(515, 130), wxLC_REPORT | wxLC_NO_HEADER);

	fileListToCrypt->InsertColumn(0, "Name", wxLIST_FORMAT_LEFT, 500);

	outputFolderStaticText = new wxStaticText(crypto, wxID_ANY, "", wxPoint(260, 170), wxSize(250, 20), wxST_NO_AUTORESIZE);

	// Note Hashing
	wxStaticBox* settings_hash = new wxStaticBox(hasher, wxID_ANY, "Hash from:", wxPoint(670, 360), wxSize(120, 90));

	open_hash_file = new wxButton(hasher, wxID_ANY, "Open file", wxPoint(0, 405), wxSize(170, 45));
	open_hash_file->Bind(wxEVT_BUTTON, &EncryptFrame::OnOpenHashFile, this);

	wxStaticText* sha3 = new wxStaticText(hasher, wxID_ANY, "SHA3:", wxPoint(5, 15), wxSize(50, 15));
	wxStaticText* sha512 = new wxStaticText(hasher, wxID_ANY, "SHA512:", wxPoint(5, 60), wxSize(50, 15));
	wxStaticText* blake2b = new wxStaticText(hasher, wxID_ANY, "Blake2b:", wxPoint(5, 105), wxSize(50, 15));
	wxStaticText* skein512 = new wxStaticText(hasher, wxID_ANY, "Skein:", wxPoint(5, 150), wxSize(50, 15));

	wxStaticText* blake2s = new wxStaticText(hasher, wxID_ANY, "Blake2s:", wxPoint(5, 195), wxSize(50, 15));
	wxStaticText* sha256 = new wxStaticText(hasher, wxID_ANY, "SHA256:", wxPoint(5, 220), wxSize(50, 15));

	wxStaticText* text = new wxStaticText(hasher, wxID_ANY, "Text:", wxPoint(5, 260), wxSize(50, 15));

	pathHashFile = new wxStaticText(hasher, wxID_ANY, "Path:", wxPoint(5, 345), wxSize(50, 30));

	sha3Text = new wxTextCtrl(hasher, wxID_ANY, "", wxPoint(60, 15), wxSize(730, 40), wxTE_MULTILINE);
	sha3Text->SetEditable(false);
	sha512Text = new wxTextCtrl(hasher, wxID_ANY, "", wxPoint(60, 60), wxSize(730, 40), wxTE_MULTILINE);
	sha512Text->SetEditable(false);
	blake2bText = new wxTextCtrl(hasher, wxID_ANY, "", wxPoint(60, 105), wxSize(730, 40), wxTE_MULTILINE);
	blake2bText->SetEditable(false);
	skeinText = new wxTextCtrl(hasher, wxID_ANY, "", wxPoint(60, 150), wxSize(730, 40), wxTE_MULTILINE);
	skeinText->SetEditable(false);

	blake2sText = new wxTextCtrl(hasher, wxID_ANY, "", wxPoint(60, 195), wxSize(730, 20), wxST_NO_AUTORESIZE);
	blake2sText->SetEditable(false);
	sha256Text = new wxTextCtrl(hasher, wxID_ANY, "", wxPoint(60, 220), wxSize(730, 20), wxST_NO_AUTORESIZE);
	sha256Text->SetEditable(false);

	hashText = new wxTextCtrl(hasher, wxID_ANY, "", wxPoint(60, 260), wxSize(730, 80), wxTE_MULTILINE);
	hashText->Enable(false);

	progress_hash = new wxGauge(hasher, wxID_ANY, 100, wxPoint(0, 455), wxSize(790, 25));

	wxRadioButton* radioFile = new wxRadioButton(hasher, wxID_ANY, "File", wxPoint(680, 385), wxDefaultSize, wxRB_GROUP);
	wxRadioButton* radioText = new wxRadioButton(hasher, wxID_ANY, "Text", wxPoint(680, 420), wxDefaultSize);

	Connect(radioFile->GetId(), wxEVT_RADIOBUTTON, wxCommandEventHandler(EncryptFrame::OnRadioFileSelected));
	Connect(radioText->GetId(), wxEVT_RADIOBUTTON, wxCommandEventHandler(EncryptFrame::OnRadioTextSelected));
}

void EncryptFrame::OnRadioTextSelected(wxCommandEvent& event)
{
	wxRadioButton* radioButton = dynamic_cast<wxRadioButton*>(event.GetEventObject());
	auto textHashes = getTextHashes();
	if (radioButton)
	{
		hashText->Clear();
		hashText->Enable(true);
		open_hash_file->SetLabel("Hash Text");
		boolHashText = true;

		for (size_t x = 0; x < textHashes.size(); ++x) textHashes[x]->Clear();

		pathHashFile->SetLabelText("Path: ");
	}

	wxString text = hashText->GetValue();
}

void EncryptFrame::OnRadioFileSelected(wxCommandEvent& event)
{
	wxRadioButton* radioButton = dynamic_cast<wxRadioButton*>(event.GetEventObject());
	auto textHashes = getTextHashes();

	if (radioButton)
	{

		hashText->Clear();
		hashText->Enable(false);
		open_hash_file->SetLabel("Open File");
		boolHashText = false;

		for (size_t x = 0; x < textHashes.size(); ++x) textHashes[x]->Clear();

		pathHashFile->SetLabelText("Path: ");
	}
}

void EncryptFrame::OnOpenHashFile(wxCommandEvent& event)
{
	CryptoManager hasher;

	auto textHashes = getTextHashes();

	if (boolHashText) {

		wxString text_for_hash = hashText->GetValue();

		std::vector<Botan::secure_vector<uint8_t>> hashResults(hashAlgorithms.size());

		Botan::secure_vector<uint8_t> vec;

		vec.resize(text_for_hash.size());
		std::copy(text_for_hash.begin(), text_for_hash.end(), vec.begin());

		for (size_t i = 0; i < hashAlgorithms.size(); ++i) {
			hashResults[i] = hasher.getHashData(vec, hashAlgorithms[i].first);
			if (!hashResults[i].empty()) {
				textHashes[i]->SetLabelText(Botan::hex_encode(hashResults[i].data(), hashResults[i].size()));
			}
			else {
				textHashes[i]->SetLabelText("Error: Unable to generate hash");
			}
		}
	}
	else {
	wxFileDialog openFileDialog(this, _("Open Key File"), "", "",
		"All files (*.*)|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);

	if (openFileDialog.ShowModal() == wxID_CANCEL) { return; }

	fullPathHashFile = openFileDialog.GetPath();

	pathHashFile->SetLabelText("Path: " + fullPathHashFile);

	std::vector<Botan::secure_vector<uint8_t>> hashResults(hashAlgorithms.size());

	for (size_t i = 0; i < hashAlgorithms.size(); ++i) {
		hashResults[i] = hasher.getHashFile(fullPathHashFile.ToStdString(), hashAlgorithms[i].first);
		if (!hashResults[i].empty()) {
			textHashes[i]->SetLabelText(Botan::hex_encode(hashResults[i].data(), hashResults[i].size()));
		}
		else {
			textHashes[i]->SetLabelText("Error: Unable to generate hash");
		}
	}
	}
}

void EncryptFrame::OnHidePassBox(wxCommandEvent& event)
{
#ifdef _WIN32
	if (hidePassCheckBox->GetValue())
	{
		SendMessageW(hWndPassword, EM_SETPASSWORDCHAR, 0, 0);
		SendMessageW(hWndConfirmPassword, EM_SETPASSWORDCHAR, 0, 0);

		passText->Refresh();
		confPassText->Refresh();
	}
	else
	{
		SendMessageW(hWndPassword, EM_SETPASSWORDCHAR, static_cast<WPARAM>('*'), 0);
		SendMessageW(hWndConfirmPassword, EM_SETPASSWORDCHAR, static_cast<WPARAM>('*'), 0);

		passText->Refresh();
		confPassText->Refresh();
	}
#endif
}

void EncryptFrame::OnEnterPass(wxCommandEvent& event)
{
	CryptoManager entropy;

	progress_pass->SetValue(entropy.calculateEntropy(passText->GetValue().ToStdString()));
}

void EncryptFrame::OnOpenCryptFile(wxCommandEvent& event)
{
	wxFileDialog openFileDialog(this, _("Open File"), "", "",
		"All files (*.*)|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST | wxFD_MULTIPLE);

	if (openFileDialog.ShowModal() == wxID_CANCEL) { return; }

	openFileDialog.GetPaths(files);

	fileListToCrypt->DeleteAllItems();

	for (const auto& file : files)
	{
		bool fileExists = false;
		for (int i = 0; i < fileListToCrypt->GetItemCount(); i++)
		{
			if (file == fileListToCrypt->GetItemText(i))
			{
				fileExists = true;
				break;
			}
		}

		if (!fileExists)
		{
			fileListToCrypt->InsertItem(fileListToCrypt->GetItemCount(), file);
		}
	}
}

void EncryptFrame::OnSaveOutputFolder(wxCommandEvent& event)
{
	wxDirDialog saveDirDialog(this, _("Select output folder"), "", wxDD_DEFAULT_STYLE | wxDD_DIR_MUST_EXIST);

	if (saveDirDialog.ShowModal() == wxID_OK)
	{
		selectedSaveDir = saveDirDialog.GetPath();
	}

	if (selectedSaveDir.length() > 45)
	{
		int halfLength = 21;

		outputFolderStaticText->SetLabelText(selectedSaveDir.Left(halfLength) + "..." + selectedSaveDir.Right(halfLength));
	}
	else {
		outputFolderStaticText->SetLabelText(selectedSaveDir);
	}
}

wxString EncryptFrame::generateNewFileName(const wxString& originalFileName, size_t index)
{
	wxFileName filePath(originalFileName);
	filePath.GetPath();

	wxString pathOnly;

	if (!selectedSaveDir.IsEmpty())
	{
		pathOnly = selectedSaveDir;
	}
	else
	{
		pathOnly = filePath.GetPath(wxPATH_GET_SEPARATOR);
	}

	return pathOnly + wxFileName::GetPathSeparator(wxPATH_NATIVE) + wxString::Format("%zd_%s", index + 1, filePath.GetFullName());
}

void EncryptFrame::OnOpenKeyFile(wxCommandEvent& event)
{
	wxFileDialog openFileDialog(this, _("Open Key File"), "", "",
		"All files (*.*)|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);

	if (openFileDialog.ShowModal() == wxID_CANCEL) { return; }

	fullPathKeyFile = openFileDialog.GetPath();

	if (fullPathKeyFile.length() > 30)
	{
		int halfLength = 13;

		fullPathKeyFile = fullPathKeyFile.Left(halfLength) + "..." + fullPathKeyFile.Right(halfLength);
	}

	keyfileStaticText->SetLabelText(fullPathKeyFile);
}

void EncryptFrame::OnKeyfileBoxChanged(wxCommandEvent& event)
{
	if (keyfile_flag->GetValue())
	{
		key_file->Enable(true);
		keyfileStaticText->Enable(true);
	}
	else
	{
		key_file->Enable(false);
		keyfileStaticText->Enable(false);
	}
}

void EncryptFrame::OnHeaderBoxChanged(wxCommandEvent& event)
{
	Botan::AutoSeeded_RNG rng;

	if (header_flag->GetValue())
	{
		cipher_choice->Enable(true);
		kdf_choice->Enable(true);

		removedStringCipher = cipher_choice->GetString(0);
		removedStringKdf = kdf_choice->GetString(0);

		cipher_choice->Delete(0);
		kdf_choice->Delete(0);

		cipher_choice->Select(static_cast<int>(rng.next_byte() % 4));
		kdf_choice->Select(static_cast<int>(rng.next_byte() / 128));

		wxMessageBox("Availability of header greatly weakens your protection!");
	}
	else
	{
		cipher_choice->Insert(removedStringCipher, 0);
		kdf_choice->Insert(removedStringKdf, 0);

		cipher_choice->Select(0);
		kdf_choice->Select(0);
	}
}

void EncryptFrame::OnCompressCheckBoxChanged(wxCommandEvent& event)
{
	if (!compress_flag->GetValue())
	{
		wxMessageBox("The lack of data compression weakens the encryption somewhat!");
	}
}

void EncryptFrame::UpdateStatus(
	wxStaticText* textKdf,
	wxStaticText* textKdfStrenth,
	wxStaticText* textCipher,
	const wxString& selectedKdf,
	size_t kdf_strength,
	const wxString& selectedCipher,
	bool header,
	bool compress,
	bool keyfile,
	Botan::secure_vector<uint8_t>& iv,
	Botan::secure_vector<uint8_t>& salt,
	Botan::secure_vector<uint8_t>& key
)
{
	std::string kdf_string = (kdf_strength == 0) ? "Low" : (kdf_strength == 1 ? "Medium" : "High");

	textKdf->SetLabelText(wxEmptyString);
	textKdfStrenth->SetLabelText(wxEmptyString);
	textCipher->SetLabelText(wxEmptyString);

	textKdf->SetLabelText("KDF algo: " + selectedKdf);
	textKdfStrenth->SetLabelText("KDF strength: " + kdf_string);
	textCipher->SetLabelText("Cipher: " + selectedCipher);

	wxString comp = compress ? "Yes" : "No";
	wxString head = header ? "Yes" : "No";
	wxString keyfil = keyfile ? "Yes" : "No";

	textHeader->SetLabelText("Header: " + head);
	textCompress->SetLabelText("Compress: " + comp);
	textKeyfile->SetLabelText("KeyFile: " + keyfil);

	textIV->SetLabelText(wxEmptyString);
	textSalt->SetLabelText(wxEmptyString);
	textKey->SetLabelText(wxEmptyString);

	wxString salt1 = Botan::hex_encode(salt.data(), salt.size());
	wxString key1 = Botan::hex_encode(key.data(), key.size());

	int halfLength = 30;

	salt1 = salt1.Left(halfLength) + "************" + salt1.Right(halfLength);
	key1 = key1.Left(halfLength) + "************" + key1.Right(halfLength);

	textIV->SetLabelText("IV: " + Botan::hex_encode(iv.data(), iv.size()));
	textSalt->SetLabelText("Salt: " + salt1);
	textKey->SetLabelText("Key: " + key1);
}

void EncryptFrame::OnEncryptFile(wxCommandEvent& event)
{
	Botan::AutoSeeded_RNG rng;

	size_t status = 0;
	wxString output;
	size_t kdfID, cipherID;
	float progress;

	CryptoManager encrypt;

	wxString pass = passText->GetValue();
	wxFileName filePath1(output);

	if (passText->IsEmpty() || confPassText->IsEmpty())
	{
		wxMessageBox(_("One or both password fields are empty"), _("Password"), wxOK | wxICON_ERROR, this);
		return;
	}

	if (passText->GetValue() != confPassText->GetValue())
	{
		wxMessageBox(_("The entered passwords do not match"), _("Password"), wxOK | wxICON_ERROR, this);
		return;
	}

	if (files.empty())
	{
		wxMessageBox(_("No file selected for encryption"), _("File"), wxOK | wxICON_ERROR, this);
		return;
	}

	if (filePath1.FileExists())
	{
		int answer = wxMessageBox(_("Encrypted file already exists. Do you want to overwrite it?"), _("File Exists"), wxYES_NO | wxYES_DEFAULT | wxICON_QUESTION, this);

		if (answer == wxNO)
		{
			return;
		}
	}

	encrypt.kdf_params.kdf_strength = kdf_slider->GetValue();

	if (keyfile_flag->GetValue()) {

		encrypt.crypto_flags.set(Crypto::KEYFILE);
		encrypt.crypto_flags.set(Crypto::ENCRYPT);

	}
	else {
		encrypt.crypto_flags.set(Crypto::ENCRYPT);
	}

	if (compress_flag->GetValue()) {
		encrypt.crypto_flags.set(Crypto::COMPRESS);
	}

	if (hard_rng_flag->GetValue()) {

		encrypt.crypto_flags.set(Crypto::HARD_RNG);

		EntropyDialog* dialog = new EntropyDialog(this, wxID_ANY, "Entropy Collector");

		dialog->SetMinSize(wxSize(815, 550));
		dialog->ShowModal();

		encrypt.key_params.seed = encrypt.getHashData(dialog->GetMouseEntropy(), "Skein-512");

		if (encrypt.key_params.seed.empty()) {

			delete dialog;
			return;
		}

		delete dialog;
	}

	if (keyfile_flag->GetValue() &&
		encrypt.crypto_flags.test(Crypto::KEYFILE) &&
		fullPathKeyFile.empty())
	{
		wxMessageBox(_("Keyfile path are empty"), _("KeyFile"), wxOK | wxICON_ERROR, this);
		return;
	}

	if (header_flag->GetValue())
	{
		encrypt.crypto_flags.set(Crypto::HEADER);
	}

	if (kdf_choice->GetStringSelection() == "Auto")
	{

		int lower_bound = 1;
		int upper_bound = kdfAlgorithms.size() - 1;

		kdfID = lower_bound + (rng.next_byte() % (upper_bound - lower_bound + 1));

		selectedKdf = kdfAlgorithms[kdfID];

		status = encrypt.deriveKeyFromPassword(
			pass.ToStdString(), 
			encrypt.kdf_params, 
			encrypt.key_params, 
			encrypt.crypto_flags, 
			selectedKdf, 
			fullPathKeyFile.ToStdString()
		);

		if (status == Crypto::ERROR_DERIVE_KEY ||
			status == Crypto::ERROR_KEYFILE_MISSING) {
			
			wxMessageBox(_("Encryption error"), _("Encrypt"), wxOK | wxICON_ERROR, this);
			return; 
		}
	}
	else
	{
		kdfID = kdf_choice->GetSelection();

		encrypt.crypto_flags.test(Crypto::HEADER) ?
			selectedKdf = getAlgo(kdfAlgorithms)[kdfID] : selectedKdf = kdfAlgorithms[kdfID];

		status = encrypt.deriveKeyFromPassword(
			pass.ToStdString(), 
			encrypt.kdf_params, 
			encrypt.key_params, 
			encrypt.crypto_flags, 
			selectedKdf, 
			fullPathKeyFile.ToStdString()
		);

		if (status == Crypto::ERROR_DERIVE_KEY ||
			status == Crypto::ERROR_KEYFILE_MISSING) {
			
			wxMessageBox(_("Encryption error"), _("Encrypt"), wxOK | wxICON_ERROR, this);
			return; 
		}
	}

	if (cipher_choice->GetStringSelection() == "Auto") {

		int lower_bound = 1;
		int upper_bound = cipherAlgorithms.size() - 1;

		cipherID = lower_bound + (rng.next_byte() % (upper_bound - lower_bound + 1));

		selectedCipher = cipherAlgorithms[cipherID];
	}
	else {

		cipherID = cipher_choice->GetSelection();

		encrypt.crypto_flags.test(Crypto::HEADER) ?
			selectedCipher = getAlgo(cipherAlgorithms)[cipherID] : selectedCipher = cipherAlgorithms[cipherID];
	}

	encrypt.header = encrypt.createEncryptFileHeader(
		VERSION,
		cipherID,
		kdfID,
		encrypt.kdf_params.kdf_strength,
		compress_flag->GetValue(),
		keyfile_flag->GetValue()
	);

	for (size_t i = 0; i < files.GetCount(); i++)
	{
		output = generateNewFileName(files[i], i);

		progress = (i + 1) * 100 / files.GetCount();
		progress_crypt->SetValue(static_cast<int>(progress));
		wxYield();

		UpdateStatus(
			textKdf,
			textKdfStrength,
			textCipher,
			selectedKdf,
			encrypt.kdf_params.kdf_strength,
			selectedCipher,
			encrypt.crypto_flags.test(Crypto::HEADER),
			encrypt.crypto_flags.test(Crypto::COMPRESS),
			encrypt.crypto_flags.test(Crypto::KEYFILE),
			encrypt.key_params.iv,
			encrypt.key_params.salt,
			encrypt.key_params.key
		);

		encrypt.encryptFile(
			files[i].ToStdString(), 
			output.ToStdString(), 
			encrypt.key_params, 
			selectedCipher, 
			encrypt.crypto_flags, 
			&encrypt.header
		);

		if (delete_flag->GetValue())
		{
			fs::remove(files[i].ToStdString());
		}
	}

	encrypt.crypto_flags.reset();
}

void EncryptFrame::OnDecryptFile(wxCommandEvent& event)
{

	size_t status = 0;
	CryptoManager decrypt;
	wxString output;
	float progress;

	if (files.empty())
	{
		wxMessageBox(_("No file selected for decryption"), _("File"), wxOK | wxICON_ERROR, this);
		return;
	}

	if ((passText->IsEmpty()))
	{
		wxMessageBox(_("Enter the decryption password in the Password field"), _("Password"), wxOK | wxICON_ERROR, this);
		return;
	}

	wxString pass = passText->GetValue();

	decrypt.kdf_params.kdf_strength = kdf_slider->GetValue();

	for (size_t i = 0; i < files.GetCount(); i++)
	{
		if (decrypt.getKeyParameters(files[i].ToStdString(), decrypt.key_params, &decrypt.header)) { // Header

			bool stop_flag = false;

			decrypt.crypto_flags.reset();

			decrypt.crypto_flags.set(Crypto::HEADER);

			if (decrypt.header.compressFlag) {
				decrypt.crypto_flags.set(Crypto::COMPRESS);
			}

			if (decrypt.header.keyfileFlag) {
				decrypt.crypto_flags.set(Crypto::KEYFILE);
				decrypt.crypto_flags.set(Crypto::DECRYPT);
			}
			else {
				decrypt.crypto_flags.set(Crypto::DECRYPT);
			}

			decrypt.kdf_params.kdf_strength = decrypt.header.kdfStrength;

			selectedKdf = getAlgo(kdfAlgorithms)[decrypt.header.kdfAlgorithmID];
			selectedCipher = getAlgo(cipherAlgorithms)[decrypt.header.encryptionAlgorithmID];

			progress = (i + 1) * 100 / files.GetCount();
			progress_crypt->SetValue(static_cast<int>(progress));
			wxYield();

			status = decrypt.deriveKeyFromPassword(
				pass.ToStdString(), 
				decrypt.kdf_params, 
				decrypt.key_params, 
				decrypt.crypto_flags, 
				selectedKdf, 
				fullPathKeyFile.ToStdString()
			);

			if (status == Crypto::ERROR_DERIVE_KEY ||
				status == Crypto::ERROR_KEYFILE_MISSING) {

				wxMessageBox(_("Decryption error"), _("Decrypt"), wxOK | wxICON_ERROR, this);
				return;
			}

			UpdateStatus(
				textKdf,
				textKdfStrength,
				textCipher,
				selectedKdf,
				decrypt.kdf_params.kdf_strength,
				selectedCipher,
				decrypt.crypto_flags.test(Crypto::HEADER),
				decrypt.header.compressFlag,
				decrypt.header.keyfileFlag,
				decrypt.key_params.iv,
				decrypt.key_params.salt,
				decrypt.key_params.key
			);

			output = generateNewFileName(files[i], i);

			decrypt.decryptFile(
				files[i].ToStdString(), 
				output.ToStdString(), 
				decrypt.key_params, 
				selectedCipher, 
				decrypt.crypto_flags,
				getAlgo(cipherAlgorithms),
				stop_flag
			);
		}
		else { // No header
			bool stop_flag = false;

			decrypt.crypto_flags.reset();

			if (keyfile_flag->GetValue()) {
				decrypt.crypto_flags.set(Crypto::KEYFILE);
				decrypt.crypto_flags.set(Crypto::DECRYPT);
			}
			else {
				decrypt.crypto_flags.set(Crypto::DECRYPT);
			}

			for (size_t kdf_strength_id = 0; kdf_strength_id <= (kdf_slider->GetMax() - kdf_slider->GetMin()); kdf_strength_id++) {

				if (stop_flag) { continue; }

				decrypt.kdf_params.kdf_strength = kdf_strength_id;

				for (size_t kdf_algo_id = 0; kdf_algo_id < 2; kdf_algo_id++)
				{
					if (stop_flag) { continue; }

					selectedKdf = getAlgo(kdfAlgorithms)[kdf_algo_id];

					status = decrypt.deriveKeyFromPassword(
						pass.ToStdString(),
						decrypt.kdf_params,
						decrypt.key_params,
						decrypt.crypto_flags,
						selectedKdf,
						fullPathKeyFile.ToStdString()
					);

					if (status == Crypto::ERROR_DERIVE_KEY ||
						status == Crypto::ERROR_KEYFILE_MISSING) {

						wxMessageBox(_("Decryption error"), _("Decrypt"), wxOK | wxICON_ERROR, this);
						return;
					}

					output = generateNewFileName(files[i], i);

					UpdateStatus(
						textKdf,
						textKdfStrength,
						textCipher,
						selectedKdf,
						decrypt.kdf_params.kdf_strength,
						decrypt.cipherAlgo,
						0,
						decrypt.compressFlag,
						0,
						decrypt.key_params.iv,
						decrypt.key_params.salt,
						decrypt.key_params.key
					);

					status = decrypt.decryptFile(
						files[i].ToStdString(),
						output.ToStdString(),
						decrypt.key_params,
						selectedCipher,
						decrypt.crypto_flags,
						getAlgo(cipherAlgorithms),
						stop_flag
					);

					if (status == Crypto::ERROR_DECRYPT) {
						wxMessageBox(_("Decryption error"), _("Decrypt"), wxOK | wxICON_ERROR, this);
					}
				}
			}

			progress = (i + 1) * 100 / files.GetCount();
			progress_crypt->SetValue(static_cast<int>(progress));
			wxYield();
		}
	}
}