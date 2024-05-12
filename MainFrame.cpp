#include "MainFrame.h"
#include "Crypto.h"

#include <wx/wx.h>
#include <wx/filename.h>
#include <wx/listctrl.h>

MainFrame::MainFrame(const wxString& title) :wxFrame(nullptr, wxID_ANY, title)
{
	wxPanel* panel = new wxPanel(this);

	// StaticBox "Enter password"
	wxStaticBox* password_box	= new wxStaticBox(panel, wxID_ANY, "Enter password", wxPoint(520, 10), wxSize(270, 240));

	wxStaticText* confim_text	= new wxStaticText(panel, wxID_ANY, "Confim password:", wxPoint(530, 95), wxSize(250, 25));
	wxStaticText* quality_text	= new wxStaticText(panel, wxID_ANY, "Password quality:", wxPoint(530, 200), wxSize(250, 25));

	passText		= new wxTextCtrl(panel, wxID_ANY, "", wxPoint(530, 60), wxSize(250, 25), wxTE_PASSWORD);
	confPassText	= new wxTextCtrl(panel, wxID_ANY, "", wxPoint(530, 120), wxSize(250, 25), wxTE_PASSWORD);

	keyfileStaticText = new wxStaticText(panel, wxID_ANY, "", wxPoint(610, 165), wxSize(170, 25), wxST_NO_AUTORESIZE);

	hidePassCheckBox = new wxCheckBox(panel, wxID_ANY, "Unhide password", wxPoint(530, 35));

	key_file = new wxButton(panel, wxID_ANY, "KeyFile", wxPoint(530, 160), wxSize(70, 25));

	hWndPassword = (HWND)passText->GetHandle();
	SendMessageW(hWndPassword, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);
	passText->Refresh();

	hWndConfirmPassword = (HWND)confPassText->GetHandle();
	SendMessageW(hWndConfirmPassword, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);
	confPassText->Refresh();

	hidePassCheckBox->	Bind(wxEVT_CHECKBOX, &MainFrame::OnHidePassBox, this);
	passText		->	Bind(wxEVT_TEXT, &MainFrame::OnEnterPass, this);
	confPassText	->	Bind(wxEVT_TEXT, &MainFrame::OnEnterPass, this);
	key_file		->	Bind(wxEVT_BUTTON, &MainFrame::OnOpenKeyFile, this);

	key_file->Enable(false);
	keyfileStaticText->Enable(false);

	// StaticBox "Encrypt settings"
	wxStaticBox* settings_box = new wxStaticBox(panel, wxID_ANY, "Encrypt settings", wxPoint(520, 260), wxSize(270, 220));

	wxStaticText* cipher_text		= new wxStaticText(panel, wxID_ANY, "Cipher:", wxPoint(530, 290), wxSize(120, 25));
	wxStaticText* derive_text		= new wxStaticText(panel, wxID_ANY, "Key derive function:", wxPoint(530, 330), wxSize(120, 25));
	wxStaticText* derive_set_text	= new wxStaticText(panel, wxID_ANY, "Key derive strong:", wxPoint(530, 370), wxSize(120, 25));

	deniability_flag	= new wxCheckBox(panel, wxID_ANY, "Deniability", wxPoint(530, 415));
	compress_flag		= new wxCheckBox(panel, wxID_ANY, "Compress", wxPoint(530, 435));
	delete_flag			= new wxCheckBox(panel, wxID_ANY, "Delete original", wxPoint(530, 455));
	keyfile_flag		= new wxCheckBox(panel, wxID_ANY, "Keyfile", wxPoint(670, 415));
	header_flag			= new wxCheckBox(panel, wxID_ANY, "Header enabled", wxPoint(670, 435));

	progress_pass		= new wxGauge(panel, wxID_ANY, 100, wxPoint(530, 225), wxSize(250, 15));

	deniability_flag->SetValue(true);

	deniabilityFlag = true;

	compress_flag		->SetValue(true);

	deniability_flag	->Bind(wxEVT_CHECKBOX, &MainFrame::OnDeniabilityCheckBoxChanged, this);
	compress_flag		->Bind(wxEVT_CHECKBOX, &MainFrame::OnCompressCheckBoxChanged, this);
	delete_flag			->Bind(wxEVT_CHECKBOX, &MainFrame::OnDeleteCheckBoxChanged, this);
	keyfile_flag		->Bind(wxEVT_CHECKBOX, &MainFrame::OnKeyfileBoxChanged, this);
	header_flag			->Bind(wxEVT_CHECKBOX, &MainFrame::OnHeaderBoxChanged, this);

	delete_flag->Enable(false);

	// StaticBox "Status"
	wxStaticBox* status_box	= new wxStaticBox(panel, wxID_ANY, "Status", wxPoint(10, 200), wxSize(400, 200));

	in_file			= new wxStaticText(panel, wxID_ANY, wxEmptyString, wxPoint(15, 215), wxSize(390, 20), wxST_NO_AUTORESIZE);

	textCipher		= new wxStaticText(panel, wxID_ANY, wxEmptyString, wxPoint(15, 235), wxSize(390, 20), wxST_NO_AUTORESIZE);
	textKdf			= new wxStaticText(panel, wxID_ANY, wxEmptyString, wxPoint(15, 255), wxSize(390, 20), wxST_NO_AUTORESIZE);
	textKdfStrenth	= new wxStaticText(panel, wxID_ANY, wxEmptyString, wxPoint(15, 275), wxSize(390, 20), wxST_NO_AUTORESIZE);


	textSalt		= new wxStaticText(panel, wxID_ANY, wxEmptyString, wxPoint(15, 355), wxSize(390, 20), wxST_NO_AUTORESIZE);
	textKey			= new wxStaticText(panel, wxID_ANY, wxEmptyString, wxPoint(15, 375), wxSize(390, 20), wxST_NO_AUTORESIZE);


	wxArrayString selectCipher;
	selectCipher.Add("Auto");
	selectCipher.Add("AES-256");
	selectCipher.Add("Serpent-256");
	selectCipher.Add("Twofish-256");
	selectCipher.Add("Camelia-256");

	cipher_choice = new wxChoice(panel, wxID_ANY, wxPoint(655, 285), wxSize(125, 30), selectCipher);
	cipher_choice->Select(0);

	cipher_choice->Bind(wxEVT_CHOICE, &MainFrame::OnCipherChoice, this);

	wxArrayString selectKdf;
	selectKdf.Add("Auto");
	selectKdf.Add("Argon2id");
	selectKdf.Add("Scrypt");

	kdf_choice = new wxChoice(panel, wxID_ANY, wxPoint(655, 325), wxSize(125, 30), selectKdf);
	kdf_choice->Select(0);

	cipher_choice->Enable(false);
	kdf_choice->Enable(false);

	kdf_choice->Bind(wxEVT_CHOICE, &MainFrame::OnKdfChoice, this);

	kdf_slider = new wxSlider(panel, wxID_ANY, 0, 0, 2, wxPoint(655, 365), wxSize(125, 30));
	kdf_slider->Bind(wxEVT_SLIDER, &MainFrame::OnKdfSlider, this);





	// Other

	encryptButton = new wxButton(panel, wxID_ANY, "Encrypt", wxPoint(10, 405), wxSize(170, 45));

	encryptButton->Bind(wxEVT_BUTTON, &MainFrame::OnEncryptFile, this);

	decryptButton = new wxButton(panel, wxID_ANY, "Decrypt", wxPoint(340, 405), wxSize(170, 45));

	decryptButton->Bind(wxEVT_BUTTON, &MainFrame::OnDecryptFile, this);

	wxButton* crypt_file = new wxButton(panel, wxID_ANY, "Select File", wxPoint(10, 160), wxSize(115, 35));

	crypt_file->Bind(wxEVT_BUTTON, &MainFrame::OnOpenCryptFile, this);

	progress_crypt = new wxGauge(panel, wxID_ANY, 100, wxPoint(10, 455), wxSize(500, 25)); 

	wxButton* output_file = new wxButton(panel, wxID_ANY, "Select output", wxPoint(135, 160), wxSize(115, 35));

	output_file->Bind(wxEVT_BUTTON, &MainFrame::OnSaveCryptFile, this);






}

void MainFrame::OnKdfSlider(wxCommandEvent& event)
{

	slider = dynamic_cast<wxSlider*>(event.GetEventObject());

	if (slider)
	{
		int selectedKdfSlider = slider->GetValue();
	}

}

void MainFrame::OnCipherChoice(wxCommandEvent& event)
{

	wxChoice* choice = dynamic_cast<wxChoice*>(event.GetEventObject());
	if (choice)
	{

		int selectedCipherNum = choice->GetSelection();

		switch (selectedCipherNum)
		{
		case 0:
			selectedCipher = "Auto";
			break;
		case 1:
			selectedCipher = "AES-256/GCM";
			break;
		case 2:
			selectedCipher = "Serpent/GCM";
			break;
		case 3:
			selectedCipher = "Twofish/GCM";
			break;
		case 4:
			selectedCipher = "Camellia-256/GCM";
			break;
		default:
			selectedCipher = "Auto";
			break;
		}

	}

}

void MainFrame::OnKdfChoice(wxCommandEvent& event)
{

	wxChoice* choice = dynamic_cast<wxChoice*>(event.GetEventObject());
	if (choice)
	{

		int selectedKdfNum = choice->GetSelection();

		switch (selectedKdfNum)
		{
		case 0:
			selectedKdf = "Auto";
			break;
		case 1:
			selectedKdf = "Argon2id";
			break;
		case 2:
			selectedKdf = "Scrypt";
			break;
		default:
			selectedKdf = "Auto";
			break;
		}
	}


}

void MainFrame::OnHidePassBox(wxCommandEvent& event)
{
	if (hidePassCheckBox->GetValue())
	{

		SendMessageW(hWndPassword, EM_SETPASSWORDCHAR, 0, 0);
		SendMessageW(hWndConfirmPassword, EM_SETPASSWORDCHAR, 0, 0);

		passText->Refresh();
		confPassText->Refresh();

	}
	else  // if disable
	{
		SendMessageW(hWndPassword, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);
		SendMessageW(hWndConfirmPassword, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);

		passText->Refresh();
		confPassText->Refresh();
	}
}

void MainFrame::OnEnterPass(wxCommandEvent& event)
{
	wxString password1 = passText->GetValue();

	int strength = calculateEntropy(password1.ToStdString());
	progress_pass->SetValue(strength);

}

void MainFrame::OnOpenCryptFile(wxCommandEvent& event)
{
    wxFileDialog openFileDialog(this, _("Open File"), "", "",
        "All files (*.*)|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);

    if (openFileDialog.ShowModal() == wxID_CANCEL)
        return;

    filePathCryptFile = openFileDialog.GetPath();

	in_file->SetLabelText(wxEmptyString);

	in_file->SetLabelText(in_file->GetLabel() + "Selected file: " + openFileDialog.GetFilename());
}

void MainFrame::OnSaveCryptFile(wxCommandEvent& event)
{
	wxFileDialog saveFileDialog(this, _("Save File"), "", "",
		"All files (*.*)|*.*", wxFD_SAVE | wxFD_OVERWRITE_PROMPT);

	if (saveFileDialog.ShowModal() == wxID_CANCEL)
		return;

	outputPathCryptFile = saveFileDialog.GetPath();
}

void MainFrame::OnOpenKeyFile(wxCommandEvent& event)
{
    wxFileDialog openFileDialog(this, _("Open Key File"), "", "",
        "All files (*.*)|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);

    if (openFileDialog.ShowModal() == wxID_CANCEL)
        return;

    fullPathKeyFile = openFileDialog.GetPath();

	if (fullPathKeyFile.length() > 30)
	{
		int middle = fullPathKeyFile.length() / 2;
		int halfLength = 13;

		fullPathKeyFile = fullPathKeyFile.Left(halfLength) + "..." + fullPathKeyFile.Right(halfLength);
	}

	keyfileStaticText->SetLabelText(fullPathKeyFile);

}

void MainFrame::OnDeniabilityCheckBoxChanged(wxCommandEvent& event)
{
	Botan::AutoSeeded_RNG rng;
	
    if (deniability_flag->GetValue())
    {
		deniabilityFlag = true;

		cipher_choice->Insert(removedStringCipher, 0);
		kdf_choice->Insert(removedStringKdf, 0);

		cipher_choice->Select(0);
		kdf_choice->Select(0);

		cipher_choice->Enable(false);
		kdf_choice->Enable(false);

		header_flag->SetValue(false);
    }
    else
    {
		deniabilityFlag = false;

		cipher_choice->Enable(true);
		kdf_choice->Enable(true);

		removedStringCipher = cipher_choice->GetString(0);
		removedStringKdf = kdf_choice->GetString(0);

		cipher_choice->Delete(0);
		kdf_choice->Delete(0);

		cipher_choice->Select(static_cast<int>(rng.next_byte() % 4));
		kdf_choice->Select(static_cast<int>(rng.next_byte() / 128));

		header_flag->SetValue(true);

        wxMessageBox("Disabling Deniability greatly weakens your protection!");
    }
}

void MainFrame::OnKeyfileBoxChanged(wxCommandEvent& event)
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

void MainFrame::OnHeaderBoxChanged(wxCommandEvent& event)
{
	Botan::AutoSeeded_RNG rng;

	if (header_flag->GetValue())
	{
		deniability_flag->SetValue(false);

		deniabilityFlag = false;

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
		deniability_flag->SetValue(true);

		deniabilityFlag = true;

		cipher_choice->Insert(removedStringCipher, 0);
		kdf_choice->Insert(removedStringKdf, 0);

		cipher_choice->Select(0);
		kdf_choice->Select(0);

		cipher_choice->Enable(false);
		kdf_choice->Enable(false);
	}
}

void MainFrame::OnCompressCheckBoxChanged(wxCommandEvent& event)
{
	
    if (compress_flag->GetValue())
    {
		compressFlag = true;
    }
    else
    {

    }
	
}

void MainFrame::OnDeleteCheckBoxChanged(wxCommandEvent& event)
{
	delete_flag->GetValue();

	
    if (delete_flag->GetValue())
    {
        wxMessageBox("wxCheckBox is checked.");
    }
    else
    {
        wxMessageBox("wxCheckBox is not checked.");
    }
	
}

void MainFrame::OnEncryptFile(wxCommandEvent& event)
{
	Botan::AutoSeeded_RNG rng;

	std::bitset<4> derive_flag;
	std::bitset<3> encrypt_flag;

	wxString pass = passText->GetValue();
	wxString output;
	KeyParameters enc_key = {};
	KdfParameters kdf_params = {};
	wxFileName filePath1(output);


	if (fullPathKeyFile.empty() && (passText->IsEmpty() || confPassText->IsEmpty()))
	{
		wxMessageBox(_("One or both password fields are empty"), _("Password"), wxOK | wxICON_ERROR, this);
		return;
	}

	if(passText->GetValue() != confPassText->GetValue())
	{ 
		wxMessageBox(_("The entered passwords do not match"), _("Password"), wxOK | wxICON_ERROR, this);
		return;
	}

	if (filePathCryptFile.empty())
	{
		wxMessageBox(_("No file selected for encryption"), _("File"), wxOK | wxICON_ERROR, this);
		return;
	}

	if (outputPathCryptFile.empty())
	{
		wxFileName filePath(filePathCryptFile);
		filePath.GetPath();
		wxString pathOnly = filePath.GetPath(wxPATH_GET_SEPARATOR);
		wxString nameOnly = "ENC_" + filePath.GetFullName();
		output = pathOnly + nameOnly;
	}
	else {
		output = outputPathCryptFile;
	}

	if (filePath1.FileExists())
	{
		int answer = wxMessageBox(_("Encrypted file already exists. Do you want to overwrite it?"), _("File Exists"), wxYES_NO | wxYES_DEFAULT | wxICON_QUESTION, this);

		if (answer == wxNO)
		{
			return;
		}
	}

	kdf_params.kdf_strength = kdf_slider->GetValue();

	if (keyfile_flag->GetValue())
	{
		derive_flag.set(KEYFILE);
		derive_flag.set(ENCRYPT);
	}
	else
	{
		derive_flag.set(ENCRYPT);
	}

	if (compress_flag->GetValue())
	{
		encrypt_flag.set(COMPRESS);
	}

	if (!deniability_flag->GetValue())
	{
		encrypt_flag.set(HEADER);
	}

	uint8_t kdfID;

	if (kdf_choice->GetStringSelection() == "Auto")		// Auto
	{
		kdfID = rng.next_byte() / 128;

		selectedKdf = kdf[static_cast<int>(kdfID)];

		derive_key_from_password(pass.ToStdString(), kdf_params, enc_key, derive_flag, selectedKdf, fullPathKeyFile.ToStdString());
	}
	else // User
	{
		kdfID = (uint8_t)kdf_choice->GetSelection();
		selectedKdf = kdf[kdf_choice->GetSelection()];
		derive_key_from_password(pass.ToStdString(), kdf_params, enc_key, derive_flag, selectedKdf, fullPathKeyFile.ToStdString());
	}

	derive_flag.reset();

	uint8_t encrID;

	if (cipher_choice->GetStringSelection() == "Auto") {	// Auto
		encrID = rng.next_byte() % 4;

		selectedCipher = algorithms[static_cast<int>(encrID)];
	}
	else {	// User
		
		encrID = (uint8_t)cipher_choice->GetSelection();
		selectedCipher = algorithms[cipher_choice->GetSelection()];
	}

	std::string kdf_string;

	switch (kdf_params.kdf_strength)
	{
	case 0:

		kdf_string = "Low";
		break;
	case 1:

		kdf_string = "Medium";
		break;
	case 2:

		kdf_string = "High";
		break;
	}
	//////////

	textKdf->SetLabelText(wxEmptyString);
	textKdfStrenth->SetLabelText(wxEmptyString);
	textCipher->SetLabelText(wxEmptyString);

	textKdf->SetLabelText(textKdf->GetLabel() + "KDF algo: " + selectedKdf);
	textKdfStrenth->SetLabelText(textKdfStrenth->GetLabel() + "KDF strenth: " + kdf_string);
	textCipher->SetLabelText(textCipher->GetLabel() + "Cipher: " + selectedCipher);

	textSalt->SetLabelText(wxEmptyString);
	textKey->SetLabelText(wxEmptyString);

	textSalt->SetLabelText(Botan::hex_encode(enc_key.salt.data(), enc_key.salt.size()));
	textKey->SetLabelText(Botan::hex_encode(enc_key.key.data(), enc_key.key.size()));
	//////////

	EncryptFileHeader header = createEncryptFileHeader(
		1,
		encrID,
		kdfID,
		kdf_params.kdf_strength,
		compress_flag->GetValue(),
		keyfile_flag->GetValue()
	);
	
	encryptFile(filePathCryptFile.ToStdString(), output.ToStdString(), enc_key, progress_crypt, selectedCipher, encrypt_flag, &header);

	encrypt_flag.reset();
}

void MainFrame::OnDecryptFile(wxCommandEvent& event)
{
	std::bitset<4> derive_flag;
	std::bitset<3> decrypt_flag;

	KeyParameters dec_key = {};
	KdfParameters kdf_params = {};
	wxString output;

	if (filePathCryptFile.empty())
	{
		wxMessageBox(_("No file selected for decryption"), _("File"), wxOK | wxICON_ERROR, this);
		return;
	}

	if (fullPathKeyFile.empty() && (passText->IsEmpty()))
	{
		wxMessageBox(_("Enter the decryption password in the Password field"), _("Password"), wxOK | wxICON_ERROR, this);
		return;
	}

    wxString pass = passText->GetValue();

	wxFileName filePath(filePathCryptFile);

	filePath.GetPath();

	wxString pathOnly = filePath.GetPath(wxPATH_GET_SEPARATOR);
	wxString nameOnly = "UN" + filePath.GetFullName();

	output = pathOnly + nameOnly;

	wxFileName filePath1(output);


	if (filePath1.FileExists())
	{
		int answer = wxMessageBox(_("Decrypted file already exists. Do you want to overwrite it?"), _("File Exists"), wxYES_NO | wxYES_DEFAULT | wxICON_QUESTION, this);

		if (answer == wxNO)
		{
			return;
		}
	}

	kdf_params.kdf_strength = kdf_slider->GetValue();

	if (keyfile_flag->GetValue())
	{
		derive_flag.set(KEYFILE);
		derive_flag.set(DECRYPT);
	}
	else
	{
		derive_flag.set(DECRYPT);
	}

	if (deniability_flag->GetValue())
	{
		decrypt_flag.set(DENIABILITY);
	}

	if (compress_flag->GetValue())
	{
		decrypt_flag.set(COMPRESS);
	}

	if (header_flag->GetValue())
	{
		decrypt_flag.set(HEADER);
	}

	bool stop_flag = false;

	EncryptFileHeader header;

	if (kdf_choice->GetStringSelection() == "Auto")
	{
		getKeyParameters(filePathCryptFile.ToStdString(), dec_key);

		for (int x = 0; x < 2; ++x)
		{

			selectedKdf = kdf[x];

			derive_key_from_password(pass.ToStdString(), kdf_params, dec_key, derive_flag, selectedKdf, fullPathKeyFile.ToStdString());

			decryptFile(filePathCryptFile.ToStdString(), output.ToStdString(), dec_key, progress_crypt, selectedCipher, decrypt_flag, stop_flag);

			if (stop_flag) break;
		}
	}
	else	// User Header
	{
		getKeyParameters(filePathCryptFile.ToStdString(), dec_key, &header);

		kdf_params.kdf_strength = header.kdfStrength;

		int selectedKdfNum = header.kdfAlgorithmID;
		switch (selectedKdfNum)
		{
		case 0:
			selectedKdf = "Argon2id";
			break;
		case 1:
			selectedKdf = "Scrypt";
			break;
		default:
			selectedKdf = "Auto";
			break;
		}

		int selectCifNum = header.encryptionAlgorithmID;
		switch (selectCifNum)
		{
		case 0:
			selectedCipher = "AES-256/GCM(16)";
			break;
		case 1:
			selectedCipher = "Serpent/GCM(16)";
			break;
		case 2:
			selectedCipher = "Twofish/GCM(16)";
			break;
		case 3:
			selectedCipher = "Camellia-256/GCM(16)";
			break;
		default:
			selectedCipher = "Auto";
			break;
		}

		derive_key_from_password(pass.ToStdString(), kdf_params, dec_key, derive_flag, selectedKdf, fullPathKeyFile.ToStdString());

		decryptFile(filePathCryptFile.ToStdString(), output.ToStdString(), dec_key, progress_crypt, selectedCipher, decrypt_flag, stop_flag, &header);
	}

	derive_flag.reset();

	std::string kdf_string;

	switch (kdf_params.kdf_strength)
	{
	case 0:

		kdf_string = "Low";
		break;
	case 1:

		kdf_string = "Medium";
		break;
	case 2:

		kdf_string = "High";
		break;
	}

	textKdf->SetLabelText(wxEmptyString);
	textKdfStrenth->SetLabelText(wxEmptyString);
	textCipher->SetLabelText(wxEmptyString);

	textKdf->SetLabelText(textKdf->GetLabel() + "KDF algo: " + selectedKdf);
	textKdfStrenth->SetLabelText(textKdfStrenth->GetLabel() + "KDF strenth: " + kdf_string);
	textCipher->SetLabelText(textCipher->GetLabel() + "Cipher: " + selectedCipher);

	textSalt->SetLabelText(wxEmptyString);
	textKey->SetLabelText(wxEmptyString);

	textSalt->SetLabelText(Botan::hex_encode(dec_key.salt.data(), dec_key.salt.size()));
	textKey->SetLabelText(Botan::hex_encode(dec_key.key.data(), dec_key.key.size()));

}