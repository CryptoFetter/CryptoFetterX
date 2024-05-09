#include <wx/wx.h>


class MainFrame : public wxFrame
{
    wxCheckBox* deniability_flag;
    wxCheckBox* compress_flag;
    wxCheckBox* delete_flag;
    wxCheckBox* keyfile_flag;

    wxButton* encryptButton;
    wxButton* decryptButton;

    wxButton* key_file;

    wxTextCtrl* passText;
    wxTextCtrl* confPassText;

    wxString filePathCryptFile;
    wxString fullPathKeyFile;

    wxTextCtrl* textCtrlPassword;
    wxTextCtrl* textCtrlPlainText;
    wxCheckBox* checkBox;

    wxGauge* progress_crypt;
    wxGauge* progress_pass;

    wxTextCtrl* keyfileTextCtrl;

    wxStaticText* statusLine1;

    HWND hWndPassword, hWndConfirmPassword;
    wxCheckBox* hidePassCheckBox;

    wxString removedStringKdf, removedStringCipher;

    std::string selectedKdf;
    std::string selectedCipher;

    wxSlider* slider;
    wxSlider* kdf_slider;

    bool deniabilityFlag;

    wxChoice* cipher_choice;
    wxChoice* kdf_choice;

    wxString textKdfAlgo, textCryptAlgo, textKdfStr;

    wxTextCtrl* textKdf;
    wxTextCtrl* textKdfStrenth;
    wxTextCtrl* textCipher;
    wxTextCtrl* textSalt;
    wxTextCtrl* textKey;

    void OnEnterPass(wxCommandEvent& event);

    void OnKdfChoice(wxCommandEvent& event);
    void OnCipherChoice(wxCommandEvent& event);

    void OnKdfSlider(wxCommandEvent& event);

public:
	MainFrame(const wxString& title);

    void OnOpenCryptFile(wxCommandEvent& event);

    void OnOpenKeyFile(wxCommandEvent& event);

    void OnDeniabilityCheckBoxChanged(wxCommandEvent& event);

    void OnCompressCheckBoxChanged(wxCommandEvent& event);

    void OnDeleteCheckBoxChanged(wxCommandEvent& event);

    void OnEncryptFile(wxCommandEvent& event);

    void OnDecryptFile(wxCommandEvent& event);

    void OnHidePassBox(wxCommandEvent& event);

    void OnKeyfileBoxChanged(wxCommandEvent& event);

};