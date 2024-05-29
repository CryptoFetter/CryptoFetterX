#include <wx/wx.h>

#include <wx/listctrl.h>
#include <wx/filename.h>

#include <filesystem>

#include "botan/aead.h"
#include "botan/auto_rng.h"
#include "botan/block_cipher.h"
#include "botan/cipher_mode.h"
#include <botan/filters.h>
#include "botan/hash.h"
#include "botan/hex.h"
#include "botan/rng.h"
#include "botan/kdf.h"
#include "botan/pwdhash.h"
#include "botan/secmem.h"
#include "botan/system_rng.h"

#define VERSION 1

class MainFrame : public wxFrame
{
    wxListCtrl* fileListToCrypt;

    wxArrayString files;

    wxString selectedSaveDir;

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

    wxTextCtrl* textCtrlPassword;
    wxTextCtrl* textCtrlPlainText;

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

    void OnEnterPass(wxCommandEvent& event);

    void OnKdfChoice(wxCommandEvent& event);
    void OnCipherChoice(wxCommandEvent& event);

    void OnKdfSlider(wxCommandEvent& event);

public:
    MainFrame(const wxString& title);

    void OnOpenCryptFile(wxCommandEvent& event);

    void OnOpenKeyFile(wxCommandEvent& event);

    void OnCompressCheckBoxChanged(wxCommandEvent& event);

    void OnDeleteCheckBoxChanged(wxCommandEvent& event);

    void OnEncryptFile(wxCommandEvent& event);

    void OnDecryptFile(wxCommandEvent& event);

    void OnHidePassBox(wxCommandEvent& event);

    void OnKeyfileBoxChanged(wxCommandEvent& event);

    void OnHeaderBoxChanged(wxCommandEvent& event);

    void OnSaveOutputFolder(wxCommandEvent& event);

    void UpdateStatus(
        wxStaticText* textKdf,
        wxStaticText* textKdfStrenth,
        wxStaticText* textCipher,
        const wxString& selectedKdf,
        uint32_t kdf_strength,
        const wxString& selectedCipher,
        bool header,
        bool compress,
        bool keyfile,
        Botan::secure_vector<uint8_t>& iv,
        Botan::secure_vector<uint8_t>& salt,
        Botan::secure_vector<uint8_t>& key
    );

    wxString generateNewFileName(const wxString& originalFileName, size_t index);
};