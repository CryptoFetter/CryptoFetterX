#ifndef ENCRYPT_FRAME_H
#define ENCRYPT_FRAME_H


#include <wx/wx.h>

#include <wx/listctrl.h>
#include <wx/notebook.h>
#include <wx/filesys.h>

#include <botan/system_rng.h>

#include <filesystem>
#include <bitset>

#define VERSION 1

class EncryptFrame : public wxFrame
{
    wxListCtrl* fileListToCrypt;

    wxArrayString files;

    wxString selectedSaveDir;

    wxCheckBox* deniability_flag;
    wxCheckBox* compress_flag;
    wxCheckBox* delete_flag;
    wxCheckBox* keyfile_flag;
    wxCheckBox* header_flag;
    wxCheckBox* hard_rng_flag;

    wxButton* encryptButton;
    wxButton* decryptButton;

    wxButton* key_file;

    wxTextCtrl* passText;
    wxTextCtrl* confPassText;

    wxString filePathCryptFile;
    wxString fullPathKeyFile;
    wxString outputPathCryptFile;

    wxString fullPathHashFile;

    wxTextCtrl* sha3Text;
    wxTextCtrl* sha512Text;
    wxTextCtrl* blake2bText;
    wxTextCtrl* blake2sText;
    wxTextCtrl* skeinText;
    wxTextCtrl* sha256Text;

    wxTextCtrl* hashText;

    wxTextCtrl* textCtrlPassword;
    wxTextCtrl* textCtrlPlainText;

    wxGauge* progress_hash;
    wxGauge* progress_crypt;
    wxGauge* progress_pass;

    wxStaticText* keyfileStaticText;
    wxStaticText* outputFolderStaticText;

    HWND hWndPassword, hWndConfirmPassword;
    wxCheckBox* hidePassCheckBox;

    wxString removedStringKdf, removedStringCipher;

    std::string selectedKdf;
    std::string selectedCipher;

    wxSlider* slider;
    wxSlider* kdf_slider;

    wxChoice* cipher_choice;
    wxChoice* kdf_choice;

    wxStaticText* textKdf;
    wxStaticText* textKdfStrength;
    wxStaticText* textCipher;
    wxStaticText* textHeader;
    wxStaticText* textCompress;
    wxStaticText* textKeyfile;

    wxStaticText* textIV;
    wxStaticText* textSalt;
    wxStaticText* textKey;

    bool boolHashText;

    wxButton* open_hash_file;

    void OnEnterPass(wxCommandEvent& event);

    void OnKdfChoice(wxCommandEvent& event);
    void OnCipherChoice(wxCommandEvent& event);

public:

    EncryptFrame(const wxString& title);

    void OnOpenCryptFile(wxCommandEvent& event);

    void OnOpenKeyFile(wxCommandEvent& event);

    void OnCompressCheckBoxChanged(wxCommandEvent& event);

    void OnEncryptFile(wxCommandEvent& event);

    void OnDecryptFile(wxCommandEvent& event);

    void OnHidePassBox(wxCommandEvent& event);

    void OnKeyfileBoxChanged(wxCommandEvent& event);

    void OnHeaderBoxChanged(wxCommandEvent& event);

    void OnSaveOutputFolder(wxCommandEvent& event);

    void OnOpenHashFile(wxCommandEvent& event);

    void UpdateStatus(
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
    );

    wxString generateNewFileName(const wxString& originalFileName, size_t index);

    void OnRadioFileSelected(wxCommandEvent& event);
    void OnRadioTextSelected(wxCommandEvent& event);

    EncryptFrame() = default;
    ~EncryptFrame() = default;
};

#endif