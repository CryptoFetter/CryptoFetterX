#include "EncryptFrame.h"
#include "Crypto.h"
#include "Secure.h"

#include "EntropyDialog.h"
#include "PassGenerator.h"
#include "zxcvbn.h"

namespace fs = std::filesystem;

EncryptFrame::EncryptFrame(const wxString& title) :wxFrame(nullptr, wxID_ANY, title)
{
	if (!localizationManager.LoadLanguage("en.xml"))
	{
		wxLogError("Failed to load localization.");
	}

	if (!ZxcvbnInit("zxcvbn.dict"))
	{
		wxLogError("Failed to load zxcvbn.dict.");
	}

	wxNotebook* notebook = new wxNotebook(this, wxID_ANY);

	wxPanel* crypto = new wxPanel(notebook);
	wxPanel* hasher = new wxPanel(notebook);
	wxPanel* passgen = new wxPanel(notebook);

	notebook->AddPage(crypto, localizationManager.GetTranslation("PAGE_ENCRYPTION"));
	notebook->AddPage(hasher, localizationManager.GetTranslation("PAGE_HASHER"));
	notebook->AddPage(passgen, localizationManager.GetTranslation("PAGE_PASSGEN"));

	// Notebook Password Generator
	wxStaticBox* password_settings = new wxStaticBox(passgen, wxID_ANY, localizationManager.GetTranslation("S_BOX_ENTER_PASS"), wxPoint(520, 10), wxSize(270, 470));

	wxStaticBox* password_1 = new wxStaticBox(passgen, wxID_ANY, localizationManager.GetTranslation("PAGE_PASSGEN"), wxPoint(0, 10), wxSize(505, 80));
	wxStaticBox* password_2 = new wxStaticBox(passgen, wxID_ANY, localizationManager.GetTranslation("PAGE_PASSGEN"), wxPoint(0, 110), wxSize(505, 80));
	wxStaticBox* password_3 = new wxStaticBox(passgen, wxID_ANY, localizationManager.GetTranslation("PAGE_PASSGEN"), wxPoint(0, 210), wxSize(505, 80));
	wxStaticBox* password_4 = new wxStaticBox(passgen, wxID_ANY, localizationManager.GetTranslation("PAGE_PASSGEN"), wxPoint(0, 310), wxSize(505, 80));

	wxButton* copy1 = new wxButton(passgen, ID_COPY_PASS1, localizationManager.GetTranslation("TEXT_COPY"), wxPoint(435, 60), wxSize(65, 25));
	copy1->Bind(wxEVT_BUTTON, &EncryptFrame::OnCopyPassword, this);

	wxButton* copy2 = new wxButton(passgen, ID_COPY_PASS2, localizationManager.GetTranslation("TEXT_COPY"), wxPoint(435, 160), wxSize(65, 25));
	copy2->Bind(wxEVT_BUTTON, &EncryptFrame::OnCopyPassword, this);

	wxButton* copy3 = new wxButton(passgen, ID_COPY_PASS3, localizationManager.GetTranslation("TEXT_COPY"), wxPoint(435, 260), wxSize(65, 25));
	copy3->Bind(wxEVT_BUTTON, &EncryptFrame::OnCopyPassword, this);

	wxButton* copy4 = new wxButton(passgen, ID_COPY_PASS4, localizationManager.GetTranslation("TEXT_COPY"), wxPoint(435, 360), wxSize(65, 25));
	copy4->Bind(wxEVT_BUTTON, &EncryptFrame::OnCopyPassword, this);

	wxButton* gen_pass = new wxButton(passgen, wxID_ANY, localizationManager.GetTranslation("BUTTON_PASSGEN"), wxPoint(0, 405), wxSize(170, 45));
	gen_pass->Bind(wxEVT_BUTTON, &EncryptFrame::OnGenPassword, this);

	spinCtrl = new wxSpinCtrl(passgen, wxID_ANY, wxEmptyString, wxPoint(530, 235), wxSize(50, 20));
	spinCtrl->SetRange(0, 65);
	spinCtrl->SetValue(15);

	alphabet1 = new wxCheckBox(passgen, wxID_ANY, localizationManager.GetTranslation("ALPA_UPPER"), wxPoint(530, 35));
	alphabet2 = new wxCheckBox(passgen, wxID_ANY, localizationManager.GetTranslation("ALPA_LOWER"), wxPoint(530, 55));
	alphabet3 = new wxCheckBox(passgen, wxID_ANY, localizationManager.GetTranslation("ALPA_DIGITS"), wxPoint(530, 75));
	alphabet4 = new wxCheckBox(passgen, wxID_ANY, localizationManager.GetTranslation("ALPA_SIMILAR"), wxPoint(530, 95));
	alphabet5 = new wxCheckBox(passgen, wxID_ANY, localizationManager.GetTranslation("ALPA_SPEC"), wxPoint(530, 115));
	alphabet6 = new wxCheckBox(passgen, wxID_ANY, localizationManager.GetTranslation("ALPA_SPACE"), wxPoint(530, 135));
	alphabet7 = new wxCheckBox(passgen, wxID_ANY, localizationManager.GetTranslation("ALPA_MINUS"), wxPoint(530, 155));
	alphabet8 = new wxCheckBox(passgen, wxID_ANY, localizationManager.GetTranslation("ALPA_BRACK"), wxPoint(530, 175));
	alphabet9 = new wxCheckBox(passgen, wxID_ANY, localizationManager.GetTranslation("ALPA_UNDERLINE"), wxPoint(530, 195));
	alphabet10 = new wxCheckBox(passgen, wxID_ANY, localizationManager.GetTranslation("ALPA_MEMORABLE"), wxPoint(530, 215));

	alphabet1->SetValue(true);
	alphabet2->SetValue(true);
	alphabet3->SetValue(true);
	alphabet5->SetValue(true);
	alphabet6->SetValue(true);
	alphabet7->SetValue(true);
	alphabet8->SetValue(true);
	alphabet9->SetValue(true);

	alphabet10->Bind(wxEVT_CHECKBOX, &EncryptFrame::OnCheckboxMemorable, this);

	pass_test1 = new wxGauge(passgen, wxID_ANY, 100, wxPoint(5, 73), wxSize(420, 10));
	pass_test2 = new wxGauge(passgen, wxID_ANY, 100, wxPoint(5, 173), wxSize(420, 10));
	pass_test3 = new wxGauge(passgen, wxID_ANY, 100, wxPoint(5, 273), wxSize(420, 10));
	pass_test4 = new wxGauge(passgen, wxID_ANY, 100, wxPoint(5, 373), wxSize(420, 10));

	pass_1 = new wxTextCtrl(passgen, wxID_ANY, "", wxPoint(5, 25), wxSize(495, 20), wxST_NO_AUTORESIZE);
	pass_2 = new wxTextCtrl(passgen, wxID_ANY, "", wxPoint(5, 125), wxSize(495, 20), wxST_NO_AUTORESIZE);
	pass_3 = new wxTextCtrl(passgen, wxID_ANY, "", wxPoint(5, 225), wxSize(495, 20), wxST_NO_AUTORESIZE);
	pass_4 = new wxTextCtrl(passgen, wxID_ANY, "", wxPoint(5, 325), wxSize(495, 20), wxST_NO_AUTORESIZE);

	// StaticBox "Enter password"
	wxStaticBox* password_box = new wxStaticBox(crypto, wxID_ANY, localizationManager.GetTranslation("S_BOX_ENTER_PASS"), wxPoint(520, 10), wxSize(270, 240));

	wxStaticText* confirm_text = new wxStaticText(crypto, wxID_ANY, localizationManager.GetTranslation("TEXT_CONFIRM_PASS"), wxPoint(530, 95), wxSize(250, 25));
	wxStaticText* quality_text = new wxStaticText(crypto, wxID_ANY, localizationManager.GetTranslation("TEXT_PASS_QUALITY"), wxPoint(530, 200), wxSize(250, 25));

	passText = new wxTextCtrl(crypto, wxID_ANY, "", wxPoint(530, 60), wxSize(250, 25), wxTE_PASSWORD);
	confPassText = new wxTextCtrl(crypto, wxID_ANY, "", wxPoint(530, 120), wxSize(250, 25), wxTE_PASSWORD);

	passText->SetMaxLength(256);
	passText->SetToolTip(localizationManager.GetTranslation("TOOLTIP_PASS_LEN"));

	confPassText->SetMaxLength(256); 
	confPassText->SetToolTip(localizationManager.GetTranslation("TOOLTIP_PASS_LEN"));

	keyfileStaticText = new wxStaticText(crypto, wxID_ANY, "", wxPoint(610, 165), wxSize(170, 25), wxST_NO_AUTORESIZE);

#ifdef _WIN32
	hidePassCheckBox = new wxCheckBox(crypto, wxID_ANY, localizationManager.GetTranslation("C_BOX_UNHIDE_PASS"), wxPoint(530, 35));
	hidePassCheckBox->Bind(wxEVT_CHECKBOX, &EncryptFrame::OnHidePassBox, this);

	hWndPassword = static_cast<HWND>(passText->GetHandle());
	SendMessageW(hWndPassword, EM_SETPASSWORDCHAR, static_cast<WPARAM>('*'), 0);
	passText->Refresh();

	hWndConfirmPassword = static_cast<HWND>(confPassText->GetHandle());
	SendMessageW(hWndConfirmPassword, EM_SETPASSWORDCHAR, static_cast<WPARAM>('*'), 0);
	confPassText->Refresh();
#endif

	key_file = new wxButton(crypto, wxID_ANY, localizationManager.GetTranslation("BUTTON_KEY_FILE"), wxPoint(530, 160), wxSize(70, 25));

	passText->Bind(wxEVT_TEXT, &EncryptFrame::OnEnterPass, this);
	confPassText->Bind(wxEVT_TEXT, &EncryptFrame::OnEnterPass, this);
	key_file->Bind(wxEVT_BUTTON, &EncryptFrame::OnOpenKeyFile, this);

	key_file->Enable(false);
	keyfileStaticText->Enable(false);

	// StaticBox "Encrypt settings"
	wxStaticBox* settings_box = new wxStaticBox(crypto, wxID_ANY, localizationManager.GetTranslation("S_BOX_ENCRYPT_SETTINGS"), wxPoint(520, 260), wxSize(270, 220));

	wxStaticText* cipher_text		= new wxStaticText(crypto, wxID_ANY, localizationManager.GetTranslation("TEXT_CIPHER"), wxPoint(530, 290), wxSize(120, 25));
	wxStaticText* derive_text		= new wxStaticText(crypto, wxID_ANY, localizationManager.GetTranslation("TEXT_KDF_FUNC"), wxPoint(530, 330), wxSize(120, 25));
	wxStaticText* derive_set_text	= new wxStaticText(crypto, wxID_ANY, localizationManager.GetTranslation("TEXT_KDF_STRONG"), wxPoint(530, 370), wxSize(120, 25));

	compress_flag	= new wxCheckBox(crypto, wxID_ANY, localizationManager.GetTranslation("C_BOX_COMPRESS"), wxPoint(530, 435));
	delete_flag		= new wxCheckBox(crypto, wxID_ANY, localizationManager.GetTranslation("C_BOX_DELETE"), wxPoint(530, 455));
	keyfile_flag	= new wxCheckBox(crypto, wxID_ANY, localizationManager.GetTranslation("C_BOX_KEYFILE"), wxPoint(670, 415));
	hard_rng_flag	= new wxCheckBox(crypto, wxID_ANY, localizationManager.GetTranslation("C_BOX_HPRNG"), wxPoint(670, 435));
	header_flag		= new wxCheckBox(crypto, wxID_ANY, localizationManager.GetTranslation("C_BOX_HEADER"), wxPoint(530, 415));

	compress_flag->SetToolTip(new wxToolTip(localizationManager.GetTranslation("TOOLTIP_COMPRESS")));
	header_flag->SetToolTip(new wxToolTip(localizationManager.GetTranslation("TOOLTIP_HEADER")));
	hard_rng_flag->SetToolTip(new wxToolTip(localizationManager.GetTranslation("TOOLTIP_USER_PRNG")));

	progress_pass = new wxGauge(crypto, wxID_ANY, 100, wxPoint(530, 225), wxSize(250, 15));

	compress_flag->SetValue(true);

	compress_flag->Bind(wxEVT_CHECKBOX, &EncryptFrame::OnCompressCheckBoxChanged, this);
	keyfile_flag->Bind(wxEVT_CHECKBOX, &EncryptFrame::OnKeyfileBoxChanged, this);
	header_flag->Bind(wxEVT_CHECKBOX, &EncryptFrame::OnHeaderBoxChanged, this);

	// StaticBox "Status"
	wxStaticBox* status_box = new wxStaticBox(crypto, wxID_ANY, localizationManager.GetTranslation("S_BOX_STATUS"), wxPoint(0, 200), wxSize(515, 200));

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
	cipher_choice->SetToolTip(localizationManager.GetTranslation("TOOLTIP_CHOICE"));
	cipher_choice->Select(0);

	wxArrayString selectKdf;

	for (const auto& algorithm : kdfAlgorithms) {
		selectKdf.Add(algorithm.second);
	}

	kdf_choice = new wxChoice(crypto, wxID_ANY, wxPoint(655, 325), wxSize(125, 30), selectKdf);
	kdf_choice->SetToolTip(localizationManager.GetTranslation("TOOLTIP_CHOICE"));
	kdf_choice->Select(0);

	kdf_slider = new wxSlider(crypto, wxID_ANY, 0, 0, 2, wxPoint(655, 365), wxSize(125, 30));

	// Other
	encryptButton = new wxButton(crypto, wxID_ANY, localizationManager.GetTranslation("BUTTON_ENCRYPT"), wxPoint(0, 405), wxSize(170, 45));
	encryptButton->Bind(wxEVT_BUTTON, &EncryptFrame::OnEncryptFile, this);

	decryptButton = new wxButton(crypto, wxID_ANY, localizationManager.GetTranslation("BUTTON_DECRYPT"), wxPoint(345, 405), wxSize(170, 45));
	decryptButton->Bind(wxEVT_BUTTON, &EncryptFrame::OnDecryptFile, this);

	wxButton* crypt_file = new wxButton(crypto, wxID_ANY, localizationManager.GetTranslation("BUTTON_SELECT_FILE"), wxPoint(0, 160), wxSize(115, 35));
	crypt_file->Bind(wxEVT_BUTTON, &EncryptFrame::OnOpenCryptFile, this);

	progress_crypt = new wxGauge(crypto, wxID_ANY, 100, wxPoint(0, 455), wxSize(515, 25));

	wxButton* output_file = new wxButton(crypto, wxID_ANY, localizationManager.GetTranslation("BUTTON_OUTPUT_FOLDER"), wxPoint(135, 160), wxSize(115, 35));
	output_file->Bind(wxEVT_BUTTON, &EncryptFrame::OnSaveOutputFolder, this);

	fileListToCrypt = new wxListCtrl(crypto, wxID_ANY, wxPoint(0, 15), wxSize(515, 130), wxLC_REPORT | wxLC_NO_HEADER);

	fileListToCrypt->InsertColumn(0, wxGetTranslation("."), wxLIST_FORMAT_LEFT, 500);

	outputFolderStaticText = new wxStaticText(crypto, wxID_ANY, "", wxPoint(260, 170), wxSize(250, 20), wxST_NO_AUTORESIZE);

	// Note Hashing
	wxStaticBox* settings_hash = new wxStaticBox(hasher, wxID_ANY, localizationManager.GetTranslation("S_BOX_HASH_FROM"), wxPoint(670, 360), wxSize(120, 90));

	open_hash_file = new wxButton(hasher, wxID_ANY, localizationManager.GetTranslation("BUTTON_OPEN_FILE"), wxPoint(0, 405), wxSize(170, 45));
	open_hash_file->Bind(wxEVT_BUTTON, &EncryptFrame::OnOpenHashFile, this);

	wxStaticText* sha3 = new wxStaticText(hasher, wxID_ANY, localizationManager.GetTranslation("TEXT_SHA3"), wxPoint(5, 15), wxSize(50, 15));
	wxStaticText* sha512 = new wxStaticText(hasher, wxID_ANY, localizationManager.GetTranslation("TEXT_SHA512"), wxPoint(5, 60), wxSize(50, 15));
	wxStaticText* blake2b = new wxStaticText(hasher, wxID_ANY, localizationManager.GetTranslation("TEXT_BLAKE2B"), wxPoint(5, 105), wxSize(50, 15));
	wxStaticText* skein512 = new wxStaticText(hasher, wxID_ANY, localizationManager.GetTranslation("TEXT_SKEIN"), wxPoint(5, 150), wxSize(50, 15));
	wxStaticText* blake2s = new wxStaticText(hasher, wxID_ANY, localizationManager.GetTranslation("TEXT_MD5"), wxPoint(5, 195), wxSize(50, 15));
	wxStaticText* sha256 = new wxStaticText(hasher, wxID_ANY, localizationManager.GetTranslation("TEXT_SHA256"), wxPoint(5, 220), wxSize(50, 15));

	wxStaticText* text = new wxStaticText(hasher, wxID_ANY, localizationManager.GetTranslation("S_BOX_TEXT"), wxPoint(5, 260), wxSize(50, 15));

	pathHashFile = new wxStaticText(hasher, wxID_ANY, localizationManager.GetTranslation("S_BOX_PATH"), wxPoint(5, 345), wxSize(50, 30));

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
	hashText->SetMaxLength(4096);
	hashText->SetToolTip(localizationManager.GetTranslation("TOOLTIP_TEXT_LEN"));
	hashText->Enable(false);

	progress_hash = new wxGauge(hasher, wxID_ANY, 100, wxPoint(0, 455), wxSize(790, 25));

	wxRadioButton* radioFile = new wxRadioButton(hasher, wxID_ANY, localizationManager.GetTranslation("RADIO_FILE"), wxPoint(680, 385), wxDefaultSize, wxRB_GROUP);
	wxRadioButton* radioText = new wxRadioButton(hasher, wxID_ANY, localizationManager.GetTranslation("RADIO_TEXT"), wxPoint(680, 420), wxDefaultSize);

	Connect(radioFile->GetId(), wxEVT_RADIOBUTTON, wxCommandEventHandler(EncryptFrame::OnRadioFileSelected));
	Connect(radioText->GetId(), wxEVT_RADIOBUTTON, wxCommandEventHandler(EncryptFrame::OnRadioTextSelected));
}

void EncryptFrame::OnCheckboxMemorable(wxCommandEvent& event)
{
	if (alphabet10->GetValue()) {

		alphabet3->SetValue(false);
		alphabet4->SetValue(false);
		alphabet5->SetValue(false);
		alphabet7->SetValue(false);
		alphabet8->SetValue(false);
		alphabet9->SetValue(false);

		alphabet3->Enable(false);
		alphabet9->Enable(false);
		alphabet5->Enable(false);
		alphabet7->Enable(false);
		alphabet8->Enable(false);
	}
	else {
		alphabet3->Enable();
		alphabet9->Enable();
		alphabet5->Enable();
		alphabet7->Enable();
		alphabet8->Enable();
	}
}

void EncryptFrame::OnRadioTextSelected(wxCommandEvent& event)
{
	auto textHashes = getTextHashes();

	wxRadioButton* radioButton = wxDynamicCast(event.GetEventObject(), wxRadioButton);
	if (radioButton)
	{
		hashText->Clear();
		hashText->Enable(true);

		open_hash_file->SetLabel(localizationManager.GetTranslation("BUTTON_HASH_TEXT"));
		boolHashText = true;

		for (auto& textHash : textHashes) {
			if (textHash) {
				textHash->Clear();
			}
		}

		pathHashFile->SetLabelText(localizationManager.GetTranslation("C_MBOX_PATH"));
	}
}

void EncryptFrame::OnCopyPassword(wxCommandEvent& event) {

	wxTextCtrl* textField = nullptr;

	switch (event.GetId()) {
	case ID_COPY_PASS1:
		textField = pass_1;
		break;
	case ID_COPY_PASS2:
		textField = pass_2;
		break;
	case ID_COPY_PASS3:
		textField = pass_3;
		break;
	case ID_COPY_PASS4:
		textField = pass_4;
		break;
	default:
		return;
	}

	if (wxTheClipboard->Open()) {
		wxTextDataObject* textData = new wxTextDataObject(textField->GetValue());

		wxTheClipboard->SetData(textData);

		wxTheClipboard->Close();
	}
}

void EncryptFrame::OnRadioFileSelected(wxCommandEvent& event)
{
	auto textHashes = getTextHashes();

	wxRadioButton* radioButton = wxDynamicCast(event.GetEventObject(), wxRadioButton);
	if (radioButton)
	{
		hashText->Clear();
		hashText->Enable(false);
		open_hash_file->SetLabel(localizationManager.GetTranslation("C_MBOX_OPEN_FILE"));
		boolHashText = false;

		for (auto& textHash : textHashes) {
			if (textHash) {
				textHash->Clear();
			}
		}

		pathHashFile->SetLabelText(localizationManager.GetTranslation("C_MBOX_PATH"));
	}
}

void EncryptFrame::OnGenPassword(wxCommandEvent& event) {

	int length = spinCtrl->GetValue();
	bool includeLowercase = alphabet2->GetValue();
	bool includeUppercase = alphabet1->GetValue();
	bool includeDigits = alphabet3->GetValue();
	bool includeSpecialChars = alphabet5->GetValue();
	bool excludeAmbiguous = alphabet4->GetValue();
	bool includeSpace = alphabet6->GetValue();
	bool includeBrackets = alphabet8->GetValue();
	bool includeMinus = alphabet7->GetValue();
	bool includeUnderlines = alphabet9->GetValue();
	bool memorable = alphabet10->GetValue();

	wxTextCtrl* passLabels[] = { pass_1, pass_2, pass_3, pass_4 };
	wxGauge* passTests[] = { pass_test1, pass_test2, pass_test3, pass_test4 };

	for (int i = 0; i < 4; ++i) {
		std::string password = generatePassword(
			length, 
			includeLowercase, 
			includeUppercase, 
			includeDigits,
			includeSpecialChars, 
			excludeAmbiguous, 
			includeSpace,
			includeBrackets, 
			includeMinus, 
			includeUnderlines, 
			memorable
		);

		int entropy = ZxcvbnMatch(password.c_str(), 0, 0);

		passLabels[i]->SetLabelText(password);
		passTests[i]->SetValue(entropy);
	}
}

void EncryptFrame::OnOpenHashFile(wxCommandEvent& event) {

	wxBusyCursor busyCursor;
	EnableAllControls(false);

	std::thread decrypt([this]() {

		FileHasher();

		wxTheApp->CallAfter([this]() {
			EnableAllControls(true);
			});

		}); decrypt.detach();
}

void EncryptFrame::OnHidePassBox(wxCommandEvent& event)
{
#ifdef _WIN32
	bool hidePass = hidePassCheckBox->GetValue();

	WPARAM passwordChar = hidePass ? 0 : static_cast<WPARAM>('*');

	if (hWndPassword && hWndConfirmPassword) {
		SendMessageW(hWndPassword, EM_SETPASSWORDCHAR, passwordChar, 0);
		SendMessageW(hWndConfirmPassword, EM_SETPASSWORDCHAR, passwordChar, 0);

		passText->Refresh();
		confPassText->Refresh();
	}
#endif
}

void EncryptFrame::OnEnterPass(wxCommandEvent& event)
{
	wxString passValue = passText->GetValue();

	if (passValue.IsEmpty()) {
		progress_pass->SetValue(0);
		return;
	}

	try {

		progress_pass->SetValue(ZxcvbnMatch(passValue.ToUTF8(), 0, 0));
	}
	catch (const std::exception) {
		progress_pass->SetValue(0);
	}
}

void EncryptFrame::OnOpenCryptFile(wxCommandEvent& event)
{
	wxFileDialog openFileDialog(this, _(localizationManager.GetTranslation("C_MBOX_OPEN_FILE")), "", "",
		localizationManager.GetTranslation("C_MBOX_ALL_FILES"), wxFD_OPEN | wxFD_FILE_MUST_EXIST | wxFD_MULTIPLE);

	if (openFileDialog.ShowModal() == wxID_CANCEL) {
		return;
	}

	openFileDialog.GetPaths(files);
	fileListToCrypt->DeleteAllItems();

	outputFolderStaticText->SetLabelText(wxFileName(files[0]).GetPath());
	selectedSaveDir = wxFileName(files[0]).GetPath();

	const wxULongLong MAX_FILE_SIZE = wxULongLong(64) * 1024 * 1024 * 1024;
	std::vector<wxString> filesList;

	for (const auto& file : files)
	{
		wxFile selectedFile(file);

		if (!selectedFile.IsOpened()) {
			continue;
		}

		wxULongLong fileSize = selectedFile.Length();

		if (fileSize > MAX_FILE_SIZE) {
			wxMessageBox(wxString::Format("%s: %s",
				_(localizationManager.GetTranslation("C_MBOX_FILE_LIMIT")),
				file.ToStdWstring()),
				_(localizationManager.GetTranslation("C_MBOX_FILE")), wxOK | wxICON_ERROR);
			continue;
		}

		if (std::find(filesList.begin(), filesList.end(), file) == filesList.end()) {
			filesList.push_back(file);
			fileListToCrypt->InsertItem(fileListToCrypt->GetItemCount(), file);
		}
	}
}

void EncryptFrame::OnSaveOutputFolder(wxCommandEvent& event)
{
	wxDirDialog saveDirDialog(this, _(localizationManager.GetTranslation("DIALOG_SELECT_OUT_FILE")), "",
		wxDD_DEFAULT_STYLE | wxDD_DIR_MUST_EXIST);

	if (saveDirDialog.ShowModal() == wxID_OK)
	{
		selectedSaveDir = saveDirDialog.GetPath();
	}

	if (!selectedSaveDir.IsEmpty()) {
		if (selectedSaveDir.length() > 45)
		{
			int halfLength = 21;
			outputFolderStaticText->SetLabelText(selectedSaveDir.Left(halfLength) + "..." + selectedSaveDir.Right(halfLength));
		}
		else {
			outputFolderStaticText->SetLabelText(selectedSaveDir);
		}
	}
}

wxString EncryptFrame::GenerateNewFileName(const wxString& originalFileName, size_t index)
{
	wxFileName filePath(originalFileName);
	filePath.Normalize(wxPATH_NORM_ALL);

	wxString pathOnly;
	if (!selectedSaveDir.IsEmpty() && wxDirExists(selectedSaveDir)) {
		pathOnly = selectedSaveDir;
	}
	else {
		pathOnly = filePath.GetPath(wxPATH_GET_SEPARATOR);
	}

	wxString newFileName = wxString::Format("%zd_%s", index + 1, filePath.GetFullName());

	return pathOnly + wxFileName::GetPathSeparator(wxPATH_NATIVE) + newFileName;
}

void EncryptFrame::OnOpenKeyFile(wxCommandEvent& event)
{
	wxFileDialog openFileDialog(this, _(localizationManager.GetTranslation("C_MBOX_OPEN_KEY_FILE")), "", "",
		localizationManager.GetTranslation("C_MBOX_ALL_FILES"), wxFD_OPEN | wxFD_FILE_MUST_EXIST);

	if (openFileDialog.ShowModal() == wxID_CANCEL) {
		return;
	}

	fullPathKeyFile = openFileDialog.GetPath();

	wxFileName fileInfo(fullPathKeyFile);
	if (!fileInfo.IsFileReadable() || fileInfo.GetSize() == 0)
	{
		wxMessageBox(_(localizationManager.GetTranslation("C_MBOX_EMPTY_FILE")),
			_(localizationManager.GetTranslation("C_MBOX_ERROR")), wxOK | wxICON_ERROR, this);
		return;
	}

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
		keyfileStaticText->SetLabelText("");
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

		wxMessageBox(localizationManager.GetTranslation("C_MBOX_HEADER_ALERT"));
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
		wxMessageBox(localizationManager.GetTranslation("C_MBOX_COMPRESS_ALERT"));
	}
}

void EncryptFrame::UpdateStatus(
	wxStaticText* textKdf,
	wxStaticText* textKdfStrength,
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
	wxString kdfStrengthString;
	switch (kdf_strength)
	{
	case 0: kdfStrengthString = localizationManager.GetTranslation("STATUS_KDF_LOW"); break;
	case 1: kdfStrengthString = localizationManager.GetTranslation("STATUS_KDF_MEDIUM"); break;
	case 2: kdfStrengthString = localizationManager.GetTranslation("STATUS_KDF_HIGHT"); break;
	default: kdfStrengthString = localizationManager.GetTranslation("STATUS_KDF_UNKNOWN"); break;
	}

	textKdf->SetLabelText(wxString::Format("%s %s", localizationManager.GetTranslation("STATUS_KDF_ALGO"), selectedKdf));
	textKdfStrength->SetLabelText(wxString::Format("%s %s", localizationManager.GetTranslation("STATUS_KDF_STRENGTH"), kdfStrengthString));
	textCipher->SetLabelText(wxString::Format("%s %s", localizationManager.GetTranslation("STATUS_CIPHER"), selectedCipher));

	textHeader->SetLabelText(wxString::Format("%s %s", localizationManager.GetTranslation("STATUS_HEADER"), header ? localizationManager.GetTranslation("STATUS_YES") : localizationManager.GetTranslation("STATUS_NO")));
	textCompress->SetLabelText(wxString::Format("%s %s", localizationManager.GetTranslation("STATUS_COMPRESS"), compress ? localizationManager.GetTranslation("STATUS_YES") : localizationManager.GetTranslation("STATUS_NO")));
	textKeyfile->SetLabelText(wxString::Format("%s %s", localizationManager.GetTranslation("STATUS_KEYFILE"), keyfile ? localizationManager.GetTranslation("STATUS_YES") : localizationManager.GetTranslation("STATUS_NO")));

#ifdef _DEBUG
	textIV->SetLabelText(wxString::Format("IV: %s", Botan::hex_encode(iv.data(), iv.size())));

	wxString saltString = Botan::hex_encode(salt.data(), salt.size());
	wxString keyString = Botan::hex_encode(key.data(), key.size());

	const int halfLength = 30;
	saltString = saltString.Left(halfLength) + "************" + saltString.Right(halfLength);
	keyString = keyString.Left(halfLength) + "************" + keyString.Right(halfLength);

	textSalt->SetLabelText(wxString::Format("Salt: %s", saltString));
	textKey->SetLabelText(wxString::Format("Key: %s", keyString));
#endif
}

void EncryptFrame::FileHasher()
{
	CryptoManager hasher;
	auto textHashes = getTextHashes();
	std::vector<Botan::secure_vector<uint8_t>> hashResults(hashAlgorithms.size());

	if (boolHashText) {
		wxString textForHash = hashText->GetValue();
		if (textForHash.IsEmpty()) {
			return;
		}

		Botan::secure_vector<uint8_t> vec(textForHash.begin(), textForHash.end());

		for (size_t i = 0; i < hashAlgorithms.size(); ++i) {
			try {
				hashResults[i] = hasher.getHashData(vec, hashAlgorithms[i].first);
				textHashes[i]->SetLabelText(Botan::hex_encode(hashResults[i].data(), hashResults[i].size()));
			}
			catch (const std::exception&) {
				textHashes[i]->SetLabelText(localizationManager.GetTranslation("TEXT_HASH_GEN_ERROR"));
			}
		}
	}
	else {
		wxFileDialog openFileDialog(
			this,
			localizationManager.GetTranslation("C_MBOX_OPEN_KEYFILE"),
			"",
			"",
			localizationManager.GetTranslation("C_MBOX_ALL_FILES"),
			wxFD_OPEN | wxFD_FILE_MUST_EXIST
		);

		if (openFileDialog.ShowModal() == wxID_CANCEL) {
			return;
		}

		fullPathHashFile = openFileDialog.GetPath();
		pathHashFile->SetLabelText(localizationManager.GetTranslation("C_MBOX_PATH") + fullPathHashFile);

		for (size_t i = 0; i < hashAlgorithms.size(); ++i) {
			try {
				hashResults[i] = hasher.getHashFile(fullPathHashFile.ToStdWstring(), hashAlgorithms[i].first);
				textHashes[i]->SetLabelText(Botan::hex_encode(hashResults[i].data(), hashResults[i].size()));
			}
			catch (const std::exception&) {
				textHashes[i]->SetLabelText(localizationManager.GetTranslation("TEXT_HASH_GEN_ERROR"));
			}
		}
	}
}

void EncryptFrame::OnEncryptFile(wxCommandEvent& event)
{
	wxBusyCursor busyCursor;
	EnableAllControls(false);

	password = passText->GetValue();

	std::thread encrypt([this]() {

		FileEncryptor();

		wxTheApp->CallAfter([this]() {
			EnableAllControls(true);
			});

		}); encrypt.detach();
}

void EncryptFrame::FileEncryptor()
{
	Botan::AutoSeeded_RNG rng;

	size_t status = 0;
	wxString output;
	size_t kdfID, cipherID;
	float progress;

	CryptoManager encrypt;

	if (passText->IsEmpty() || confPassText->IsEmpty())
	{
		wxMessageBox(_(localizationManager.GetTranslation("C_MBOX_PASSWORD_EMPTY")), _(localizationManager.GetTranslation("C_MBOX_PASSWORD")), wxOK | wxICON_ERROR, this);
		return;
	}

	if (passText->GetValue() != confPassText->GetValue())
	{
		wxMessageBox(_(localizationManager.GetTranslation("C_MBOX_PASSWORD_MATCH")), _(localizationManager.GetTranslation("C_MBOX_PASSWORD")), wxOK | wxICON_ERROR, this);
		return;
	}

	if (files.empty())
	{
		wxMessageBox(_(localizationManager.GetTranslation("C_MBOX_ENCRYPT_NOFILE")), _(localizationManager.GetTranslation("C_MBOX_FILE")), wxOK | wxICON_ERROR, this);
		return;
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

		EntropyDialog* dialog = new EntropyDialog(this, wxID_ANY, localizationManager.GetTranslation("DIALOG_ENTROPY"));

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
		wxMessageBox(_(localizationManager.GetTranslation("C_MBOX_KEYFILE_PATH")), _(localizationManager.GetTranslation("C_BOX_KEYFILE")), wxOK | wxICON_ERROR, this);
		return;
	}

	if (header_flag->GetValue())
	{
		encrypt.crypto_flags.set(Crypto::HEADER);
	}

	if (kdf_choice->GetStringSelection() == "Auto")
	{

		size_t lower_bound = 1;
		size_t upper_bound = kdfAlgorithms.size() - 1;

		kdfID = lower_bound + (rng.next_byte() % (upper_bound - lower_bound + 1));

		selectedKdf = kdfAlgorithms[kdfID];

		status = encrypt.deriveKeyFromPassword(
			password.ToStdString(), 
			encrypt.kdf_params, 
			encrypt.key_params, 
			encrypt.crypto_flags, 
			selectedKdf, 
			fullPathKeyFile.ToStdWstring()
		);

		if (status == Crypto::ERROR_DERIVE_KEY ||
			status == Crypto::ERROR_KEYFILE_MISSING) {
			
			wxMessageBox(_(localizationManager.GetTranslation("C_MBOX_ENCRYPT_ERROR")), _(localizationManager.GetTranslation("C_MBOX_ENCRYPT")), wxOK | wxICON_ERROR, this);
			return; 
		}
	}
	else
	{
		kdfID = kdf_choice->GetSelection();

		encrypt.crypto_flags.test(Crypto::HEADER) ?
			selectedKdf = getAlgo(kdfAlgorithms)[kdfID] : selectedKdf = kdfAlgorithms[kdfID];

		status = encrypt.deriveKeyFromPassword(
			password.ToStdString(), 
			encrypt.kdf_params, 
			encrypt.key_params, 
			encrypt.crypto_flags, 
			selectedKdf, 
			fullPathKeyFile.ToStdWstring()
		);

		if (status == Crypto::ERROR_DERIVE_KEY ||
			status == Crypto::ERROR_KEYFILE_MISSING) {
			
			wxMessageBox(_(localizationManager.GetTranslation("C_MBOX_ENCRYPT_ERROR")), _(localizationManager.GetTranslation("C_MBOX_ENCRYPT")), wxOK | wxICON_ERROR, this);
			return; 
		}
	}

	if (cipher_choice->GetStringSelection() == "Auto") {

		size_t lower_bound = 1;
		size_t upper_bound = cipherAlgorithms.size() - 1;

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
		output = GenerateNewFileName(files[i], i);

		if (wxFileName::FileExists(output))
		{
			int answer = wxMessageBox(_(localizationManager.GetTranslation("C_MBOX_ENCRYPT_FILE_EXIST") + " " + output), _(localizationManager.GetTranslation("C_MBOX_FILE")), wxYES_NO | wxYES_DEFAULT | wxICON_QUESTION, this);

			if (answer == wxNO)
			{
				return;
			}
		}

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

		size_t status = encrypt.encryptFile(
			files[i].ToStdWstring(),
			output.ToStdWstring(),
			encrypt.key_params, 
			selectedCipher, 
			encrypt.crypto_flags, 
			&encrypt.header
		);

		switch (status) {
		case Crypto::ERROR_ENCRYPT:
			wxMessageBox(wxString::Format("%s: %s",
				_(localizationManager.GetTranslation("C_MBOX_ENCRYPT_ERROR")),
				files[i].ToStdString()),
				_(localizationManager.GetTranslation("C_MBOX_FILE")), wxOK | wxICON_INFORMATION);
			break;
		case Crypto::ERROR_OPEN_FILE:
			wxMessageBox(wxString::Format("%s: %s",
				_(localizationManager.GetTranslation("C_MBOX_UNABLE_OPEN_FILE")),
				files[i].ToStdString()),
				_(localizationManager.GetTranslation("C_MBOX_FILE")), wxOK | wxICON_INFORMATION);
			break;
		default:
			break;
		}

		progress = (i + 1) * 100 / files.GetCount();
		progress_crypt->SetValue(static_cast<int>(progress));
		wxYield();

		if (delete_flag->GetValue())
		{
			fs::remove(files[i].ToStdString());
		}
	}

	eraseMemory((void*)encrypt.key_params.key.data(), encrypt.key_params.key.size());
	encrypt.crypto_flags.reset();

	passText->Clear();
	confPassText->Clear();
}

void EncryptFrame::OnDecryptFile(wxCommandEvent& event)
{
	wxBusyCursor busyCursor;
	EnableAllControls(false);

	password = passText->GetValue();

	std::thread decrypt([this]() {

		FileDecryptor();

		wxTheApp->CallAfter([this]() {
			EnableAllControls(true);
			});

		}); decrypt.detach();
}

void EncryptFrame::FileDecryptor()
{
	size_t status = 0;
	CryptoManager decrypt;
	wxString output;
	float progress;

	if (files.empty())
	{
		wxMessageBox(_(localizationManager.GetTranslation("C_MBOX_DECRYPT_FILE_SELECTED")), _(localizationManager.GetTranslation("C_MBOX_FILE")), wxOK | wxICON_ERROR, this);
		return;
	}

	if ((passText->IsEmpty()))
	{
		wxMessageBox(_(localizationManager.GetTranslation("C_MBOX_DECRYPT_PASS_ERROR")), _(localizationManager.GetTranslation("C_MBOX_PASSWORD")), wxOK | wxICON_ERROR, this);
		return;
	}

	decrypt.kdf_params.kdf_strength = kdf_slider->GetValue();

	for (size_t i = 0; i < files.GetCount(); i++)
	{
		std::atomic<bool> stop_flag = false;

		output = GenerateNewFileName(files[i], i);

		if (wxFileName::FileExists(output))
		{
			int answer = wxMessageBox(_(localizationManager.GetTranslation("C_MBOX_DECRYPT_FILE_EXIST")), _(localizationManager.GetTranslation("C_MBOX_FILE")), wxYES_NO | wxYES_DEFAULT | wxICON_QUESTION, this);

			if (answer == wxNO)
			{
				continue;
			}
		}

		if (decrypt.getKeyParameters(files[i].ToStdWstring(), decrypt.key_params, &decrypt.header)) { // Header

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

			status = decrypt.deriveKeyFromPassword(
				password.ToStdString(), 
				decrypt.kdf_params, 
				decrypt.key_params, 
				decrypt.crypto_flags, 
				selectedKdf, 
				fullPathKeyFile.ToStdWstring()
			);

			if (status == Crypto::ERROR_DERIVE_KEY ||
				status == Crypto::ERROR_KEYFILE_MISSING) {

				wxMessageBox(_(localizationManager.GetTranslation("C_MBOX_DECRYPT_ERROR")), _(localizationManager.GetTranslation("C_MBOX_DECRYPT")), wxOK | wxICON_ERROR, this);
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

			size_t status = decrypt.decryptFile(
				files[i].ToStdWstring(),
				output.ToStdWstring(),
				decrypt.key_params, 
				selectedCipher, 
				decrypt.crypto_flags,
				getAlgo(cipherAlgorithms),
				stop_flag,
				&decrypt.header
			);

			switch (status) {
			case Crypto::ERROR_DECRYPT:
				wxMessageBox(wxString::Format("%s: %s",
					_(localizationManager.GetTranslation("C_MBOX_DECRYPT_ERROR")),
					files[i].ToStdString()),
					_(localizationManager.GetTranslation("C_MBOX_FILE")), wxOK | wxICON_INFORMATION);
				break;
			case Crypto::ERROR_OPEN_FILE:
				wxMessageBox(wxString::Format("%s: %s",
					_(localizationManager.GetTranslation("C_MBOX_DECRYPT_ERROR")),
					files[i].ToStdString()),
					_(localizationManager.GetTranslation("C_MBOX_FILE")), wxOK | wxICON_INFORMATION);
				break;
			default:
				break;
			}
		}
		else { // No header

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

				for (size_t kdf_algo_id = 0; kdf_algo_id < (kdf_choice->GetCount() - 1); kdf_algo_id++)
				{
					if (stop_flag) { continue; }

					selectedKdf = getAlgo(kdfAlgorithms)[kdf_algo_id];

					status = decrypt.deriveKeyFromPassword(
						password.ToStdString(),
						decrypt.kdf_params,
						decrypt.key_params,
						decrypt.crypto_flags,
						selectedKdf,
						fullPathKeyFile.ToStdWstring()
					);

					if (status == Crypto::ERROR_DERIVE_KEY ||
						status == Crypto::ERROR_KEYFILE_MISSING) {

						wxMessageBox(_(localizationManager.GetTranslation("C_MBOX_DECRYPT_ERROR")), _(localizationManager.GetTranslation("C_MBOX_DECRYPT")), wxOK | wxICON_ERROR, this);
						return;
					}

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
						files[i].ToStdWstring(),
						output.ToStdWstring(),
						decrypt.key_params,
						selectedCipher,
						decrypt.crypto_flags,
						getAlgo(cipherAlgorithms),
						stop_flag
					);
				}
			}

			switch (status) {
			case Crypto::ERROR_DECRYPT:
				wxMessageBox(wxString::Format("%s: %s",
					_(localizationManager.GetTranslation("C_MBOX_DECRYPT_ERROR")),
					files[i].ToStdString()),
					_(localizationManager.GetTranslation("C_MBOX_FILE")), wxOK | wxICON_INFORMATION);
				break;
			case Crypto::ERROR_OPEN_FILE:
				wxMessageBox(wxString::Format("%s: %s",
					_(localizationManager.GetTranslation("C_MBOX_DECRYPT_ERROR")),
					files[i].ToStdString()),
					_(localizationManager.GetTranslation("C_MBOX_FILE")), wxOK | wxICON_INFORMATION);
				break;
			default:
				break;
			}
		}

		progress = (i + 1) * 100 / files.GetCount();
		progress_crypt->SetValue(static_cast<int>(progress));
		wxYield();
	}

	eraseMemory((void*)decrypt.key_params.key.data(), decrypt.key_params.key.size());

	passText->Clear();
	confPassText->Clear();
}

void EncryptFrame::EnableAllControls(bool enable)
{
	wxWindowList& children = this->GetChildren();
	for (wxWindowList::iterator it = children.begin(); it != children.end(); ++it)
	{
		wxWindow* child = *it;
		if (child && !wxDynamicCast(child, wxGauge))
		{
			child->Enable(enable);
		}
	}
}