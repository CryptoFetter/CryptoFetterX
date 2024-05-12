#include <wx/wx.h>


class MainFrame : public wxFrame
{
    wxCheckBox* deniability_flag;
    wxCheckBox* compress_flag;
    wxCheckBox* delete_flag;
    wxCheckBox* keyfile_flag;
    wxCheckBox* header_flag;

    wxButton* encryptButton;
    wxButton* decryptButton;

    wxButton* key_file;

    wxTextCtrl* passText;
    wxTextCtrl* confPassText;

    wxString filePathCryptFile;
    wxString fullPathKeyFile;
    wxString outputPathCryptFile;

    wxTextCtrl* textCtrlPassword;   // 
    wxTextCtrl* textCtrlPlainText;  // 

    wxGauge* progress_crypt;
    wxGauge* progress_pass;

    wxStaticText* keyfileStaticText;    //

    HWND hWndPassword, hWndConfirmPassword;
    wxCheckBox* hidePassCheckBox;

    wxString removedStringKdf, removedStringCipher;

    std::string selectedKdf;
    std::string selectedCipher;

    wxSlider* slider;
    wxSlider* kdf_slider;

    bool deniabilityFlag;
    bool compressFlag;

    wxChoice* cipher_choice;
    wxChoice* kdf_choice;

    wxStaticText* in_file;

    wxStaticText* textKdf;
    wxStaticText* textKdfStrenth;
    wxStaticText* textCipher;
    wxStaticText* textSalt;
    wxStaticText* textKey;

    void OnEnterPass(wxCommandEvent& event);
    void UpdateGaugeColor(int value);

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

    void OnHeaderBoxChanged(wxCommandEvent& event);

    void OnSaveCryptFile(wxCommandEvent& event);

};