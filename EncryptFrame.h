﻿#ifndef ENCRYPT_FRAME_H
#define ENCRYPT_FRAME_H


#include <wx/wx.h>

#include <wx/listctrl.h>
#include <wx/notebook.h>
#include <wx/filesys.h>
#include <wx/thread.h>
#include <wx/xml/xml.h>
#include <wx/xrc/xmlres.h>
#include <wx/file.h>

#include <botan/system_rng.h>

#include <filesystem>
#include <bitset>
#include <map>

#include "Local.h"

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
    wxStaticText* pathHashFile;

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

    std::vector<std::pair<std::string, size_t>> hashAlgorithms = {
    {"SHA-3(512)", 512},
    {"SHA-512", 512},
    {"SHA-256", 256},
    {"Skein-512(512)", 512},
    {"BLAKE2b(512)", 512},
    {"MD5", 128}
    };

    std::map<int, std::string> kdfAlgorithms = {
        {0, "Auto"},
        {1, "Argon2id"},
        {2, "Scrypt"}
    };

    std::map<int, std::string> cipherAlgorithms = {
        {0, "Auto"},
        {1, "AES-256/GCM"},
        {2, "Serpent/GCM"},
        {3, "Twofish/GCM"},
        {4, "Camellia-256/GCM"}
    };

    LocalizationManager localizationManager;

public:

    EncryptFrame(const wxString& title);

    void EnableAllControls(bool enable);

    void OnOpenCryptFile(wxCommandEvent& event);

    void OnOpenKeyFile(wxCommandEvent& event);

    void OnCompressCheckBoxChanged(wxCommandEvent& event);

    void OnEncryptFile(wxCommandEvent& event);

    void OnDecryptFile(wxCommandEvent& event);

    void FileDecryptor();
    void FileEncryptor();

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

    wxString GenerateNewFileName(const wxString& originalFileName, size_t index);

    void OnRadioFileSelected(wxCommandEvent& event);
    void OnRadioTextSelected(wxCommandEvent& event);

    std::vector<std::string> getAlgo(const std::map<int, std::string>& cipherAlgorithms) {
        std::vector<std::string> algorithms;

        auto it = cipherAlgorithms.begin();
        if (it != cipherAlgorithms.end()) {
            ++it;
        }

        for (; it != cipherAlgorithms.end(); ++it) {
            algorithms.push_back(it->second);
        }

        return algorithms;
    }

    std::vector<wxTextCtrl*> getTextHashes() {
        return { sha3Text, sha512Text, sha256Text, skeinText, blake2bText, blake2sText };
    }

    EncryptFrame() = default;
    ~EncryptFrame() = default;
};

#endif