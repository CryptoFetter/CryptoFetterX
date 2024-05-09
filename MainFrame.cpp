#include "MainFrame.h"
#include "Crypto.h"

#include <wx/wx.h>
#include <wx/filename.h>


MainFrame::MainFrame(const wxString& title) :wxFrame(nullptr, wxID_ANY, title)
{
	wxPanel* panel = new wxPanel(this);

	// StaticBox "Enter password"
	wxStaticBox* password_box = new wxStaticBox(panel, wxID_ANY, "Enter password", wxPoint(520, 10), wxSize(270, 240));

	wxStaticText* confirm_text = new wxStaticText(panel, wxID_ANY, "Confirm password:", wxPoint(530, 95), wxSize(250, 25));
	wxStaticText* quality_text = new wxStaticText(panel, wxID_ANY, "Password quality:", wxPoint(530, 200), wxSize(250, 25));

	passText = new wxTextCtrl(panel, wxID_ANY, "", wxPoint(530, 60), wxSize(250, 25), wxTE_PASSWORD);
	confPassText = new wxTextCtrl(panel, wxID_ANY, "", wxPoint(530, 120), wxSize(250, 25), wxTE_PASSWORD);
	keyfileTextCtrl = new wxTextCtrl(panel, wxID_ANY, "", wxPoint(610, 160), wxSize(170, 25), wxTE_PROCESS_ENTER);

	hidePassCheckBox = new wxCheckBox(panel, wxID_ANY, "Unhide password", wxPoint(530, 35));

	key_file = new wxButton(panel, wxID_ANY, "KeyFile", wxPoint(530, 160), wxSize(70, 25));

	hWndPassword = (HWND)passText->GetHandle();
	SendMessageW(hWndPassword, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);
	passText->Refresh();

	hWndConfirmPassword = (HWND)confPassText->GetHandle();
	SendMessageW(hWndConfirmPassword, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);
	confPassText->Refresh();

	hidePassCheckBox->Bind(wxEVT_CHECKBOX, &MainFrame::OnHidePassBox, this);
	passText->Bind(wxEVT_TEXT, &MainFrame::OnEnterPass, this);
	confPassText->Bind(wxEVT_TEXT, &MainFrame::OnEnterPass, this);
	key_file->Bind(wxEVT_BUTTON, &MainFrame::OnOpenKeyFile, this);

	key_file->Enable(false);
	keyfileTextCtrl->Enable(false);

	// StaticBox "Encrypt settings"
	wxStaticBox* settings_box = new wxStaticBox(panel, wxID_ANY, "Encrypt settings", wxPoint(520, 260), wxSize(270, 220));

	deniability_flag = new wxCheckBox(panel, wxID_ANY, "Deniability", wxPoint(530, 415));
	compress_flag = new wxCheckBox(panel, wxID_ANY, "Compress", wxPoint(530, 435));
	delete_flag = new wxCheckBox(panel, wxID_ANY, "Delete original", wxPoint(530, 455));
	keyfile_flag = new wxCheckBox(panel, wxID_ANY, "Keyfile", wxPoint(670, 415));

	progress_pass = new wxGauge(panel, wxID_ANY, 100, wxPoint(530, 225), wxSize(250, 15));

	deniability_flag->SetValue(true);
	deniability_flag->Enable(false);

	deniabilityFlag = true;

	deniability_flag->Bind(wxEVT_CHECKBOX, &MainFrame::OnDeniabilityCheckBoxChanged, this);
	compress_flag->Bind(wxEVT_CHECKBOX, &MainFrame::OnCompressCheckBoxChanged, this);
	delete_flag->Bind(wxEVT_CHECKBOX, &MainFrame::OnDeleteCheckBoxChanged, this);
	keyfile_flag->Bind(wxEVT_CHECKBOX, &MainFrame::OnKeyfileBoxChanged, this);

	compress_flag->Enable(false);
	delete_flag->Enable(false);
	//keyfile_flag->Enable(false);

	// StaticBox "Status"
	wxStaticBox* status_box = new wxStaticBox(panel, wxID_ANY, "Status", wxPoint(10, 260), wxSize(400, 130));

	wxStaticText* cipher_text = new wxStaticText(panel, wxID_ANY, "Cipher:", wxPoint(530, 290), wxSize(100, 25));
	wxStaticText* derive_text = new wxStaticText(panel, wxID_ANY, "Key derive function:", wxPoint(530, 330), wxSize(120, 25));
	wxStaticText* derive_set_text = new wxStaticText(panel, wxID_ANY, "Key derive strong:", wxPoint(530, 370), wxSize(120, 25));


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

	wxButton* crypt_file = new wxButton(panel, wxID_ANY, "Select File", wxPoint(10, 160), wxSize(105, 35));
	crypt_file->Bind(wxEVT_BUTTON, &MainFrame::OnOpenCryptFile, this);

	progress_crypt = new wxGauge(panel, wxID_ANY, 100, wxPoint(10, 455), wxSize(500, 25)); 
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
	else
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

	wxString fileCryptFile = openFileDialog.GetFilename();

	fileCryptFile = "Selected file: " + fileCryptFile;
	
	wxTextCtrl* in_file = new wxTextCtrl(this, wxID_ANY, fileCryptFile, wxPoint(10, 275), wxSize(390, 25), wxTE_READONLY);
}

void MainFrame::OnOpenKeyFile(wxCommandEvent& event)
{
    wxFileDialog openFileDialog(this, _("Open Key File"), "", "",
        "All files (*.*)|*.*", wxFD_OPEN | wxFD_FILE_MUST_EXIST);

    if (openFileDialog.ShowModal() == wxID_CANCEL)
        return;

    fullPathKeyFile = openFileDialog.GetPath();

	keyfileTextCtrl->SetValue(fullPathKeyFile);
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

        wxMessageBox("Disabling Deniability greatly weakens your protection!");
    }
}

void MainFrame::OnKeyfileBoxChanged(wxCommandEvent& event)
{
	if (keyfile_flag->GetValue())
	{
		key_file->Enable(true);
		keyfileTextCtrl->Enable(true);
	}
	else
	{
		key_file->Enable(false);
		keyfileTextCtrl->Enable(false);
	}
}

void MainFrame::OnCompressCheckBoxChanged(wxCommandEvent& event)
{
	compress_flag->GetValue();
}

void MainFrame::OnDeleteCheckBoxChanged(wxCommandEvent& event)
{
	delete_flag->GetValue();
}

void MainFrame::OnEncryptFile(wxCommandEvent& event)
{
	Botan::AutoSeeded_RNG rng;

	std::bitset<3> flag;

	wxString pass = passText->GetValue();
	wxString output;
	KeyParameters enc_key = {};
	wxFileName filePath1(output);
	KdfParameters kdf_params;

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

	wxFileName filePath(filePathCryptFile);
	filePath.GetPath();
	wxString pathOnly = filePath.GetPath(wxPATH_GET_SEPARATOR);
	wxString nameOnly = "ENC_" + filePath.GetFullName();
	output = pathOnly + nameOnly;

	if (filePath1.FileExists())
	{
		int answer = wxMessageBox(_("Encrypted file already exists. Do you want to overwrite it?"), _("File Exists"), wxYES_NO | wxYES_DEFAULT | wxICON_QUESTION, this);

		if (answer == wxNO)
		{
			return;
		}
	}

	kdf_params.kdf_strenth = kdf_slider->GetValue();

	if (keyfile_flag->GetValue())
	{
		flag.set(KEYFILE);
		flag.set(ENCRYPT);
	}
	else
	{
		flag.set(ENCRYPT);
	}

	if (kdf_choice->GetStringSelection() == "Auto")
	{
		selectedKdf = kdf[static_cast<int>(rng.next_byte() / 128)];

		derive_key_from_password(pass.ToStdString(), kdf_params, enc_key, flag, selectedKdf, fullPathKeyFile.ToStdString());
	}
	else
	{	
		selectedKdf = kdf[kdf_choice->GetSelection()];
		derive_key_from_password(pass.ToStdString(), kdf_params, enc_key, flag, selectedKdf, fullPathKeyFile.ToStdString());
	}

	flag.reset();

	if (cipher_choice->GetStringSelection() == "Auto") {	// Auto
		selectedCipher = algorithms[static_cast<int>(rng.next_byte() % 4)]; 	// число от 0 до 3
	}
	else {
		selectedCipher = algorithms[cipher_choice->GetSelection()];
	}

	std::string kdf_string;

	switch (kdf_params.kdf_strenth)
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

	textKdfAlgo = "KDF algo: " + selectedKdf;
	textKdfStr = "KDF strenth: " + kdf_string;
	textCryptAlgo = "Cipher: " + selectedCipher;

	textKdf = new wxTextCtrl(this, wxID_ANY, textKdfAlgo, wxPoint(10, 295), wxSize(390, 25), wxTE_READONLY);
	textKdfStrenth = new wxTextCtrl(this, wxID_ANY, textKdfStr, wxPoint(10, 315), wxSize(390, 25), wxTE_READONLY);
	textCipher = new wxTextCtrl(this, wxID_ANY, textCryptAlgo, wxPoint(10, 335), wxSize(390, 25), wxTE_READONLY);

	encryptFile(filePathCryptFile.ToStdString(), output.ToStdString(), enc_key, progress_crypt, selectedCipher);
}

void MainFrame::OnDecryptFile(wxCommandEvent& event)
{
	std::bitset<3> flag;

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

	KeyParameters dec_key = {};
	wxString output;

	KdfParameters kdf_params;

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

	getKeyParameters(filePathCryptFile.ToStdString(), dec_key);

	kdf_params.kdf_strenth = kdf_slider->GetValue();

	if (keyfile_flag->GetValue())
	{
		flag.set(KEYFILE);
		flag.set(DECRYPT);
	}
	else
	{
		flag.set(DECRYPT);
	}

	bool stop_flag = false;

	if (kdf_choice->GetStringSelection() == "Auto")
	{
		for (int x = 0; x < 2; ++x)
		{

			selectedKdf = kdf[x];

			derive_key_from_password(pass.ToStdString(), kdf_params, dec_key, flag, selectedKdf, fullPathKeyFile.ToStdString());

			decryptFile(filePathCryptFile.ToStdString(), output.ToStdString(), dec_key, progress_crypt, selectedCipher, deniabilityFlag, stop_flag);

			if (stop_flag) break;
		}
	}
	else
	{
		selectedKdf = kdf[kdf_choice->GetSelection()];
		selectedCipher = algorithms[cipher_choice->GetSelection()];

		derive_key_from_password(pass.ToStdString(), kdf_params, dec_key, flag, selectedKdf, fullPathKeyFile.ToStdString());

		decryptFile(filePathCryptFile.ToStdString(), output.ToStdString(), dec_key, progress_crypt, selectedCipher, deniabilityFlag, stop_flag);
	}

	flag.reset();

	std::string kdf_string;

	switch (kdf_params.kdf_strenth)
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


	textKdfAlgo = "KDF algo: " + selectedKdf;
	textKdfStr = "KDF strenth: " + kdf_string;
	textCryptAlgo = "Cipher: " + selectedCipher;

	textKdf = new wxTextCtrl(this, wxID_ANY, textKdfAlgo, wxPoint(10, 295), wxSize(390, 25), wxTE_READONLY);
	textKdfStrenth = new wxTextCtrl(this, wxID_ANY, textKdfStr, wxPoint(10, 315), wxSize(390, 25), wxTE_READONLY);
	textCipher = new wxTextCtrl(this, wxID_ANY, textCryptAlgo, wxPoint(10, 335), wxSize(390, 25), wxTE_READONLY);
}