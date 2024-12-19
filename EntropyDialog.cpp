#include "EntropyDialog.h"
#include "Crypto.h"


EntropyDialog::EntropyDialog(wxWindow* parent, wxWindowID id, const wxString& title)
    : wxDialog(parent, id, title, wxDefaultPosition, wxSize(815, 550), wxDEFAULT_DIALOG_STYLE & ~wxCLOSE_BOX)
{
    
    if (!localizationManager.LoadLanguage("en.xml"))
    {
        wxLogError("Failed to load localization.");
    }

    wxPanel* entropyCollector = new wxPanel(this);

    wxStaticText* staticText = new wxStaticText(entropyCollector, wxID_ANY, localizationManager.GetTranslation("TEXT_ENTROPY"),
        wxPoint(5, 5), wxSize(805, 64), wxALIGN_CENTRE | wxST_NO_AUTORESIZE);

    wxFont font(16, wxFONTFAMILY_DEFAULT, wxFONTSTYLE_NORMAL, wxFONTWEIGHT_NORMAL);
    staticText->SetFont(font);

    entropyCollector->Bind(wxEVT_MOTION, &EntropyDialog::OnMouseEvent, this);

    progress_entropy = new wxGauge(entropyCollector, wxID_ANY, 2048, wxPoint(5, 455), wxSize(790, 25));
};

void EntropyDialog::OnMouseEvent(wxMouseEvent& evt) {

    CryptoManager encrypt;

    wxPoint mousePos = evt.GetPosition();

    unsigned char x_byte = static_cast<unsigned char>(mousePos.x);
    unsigned char y_byte = static_cast<unsigned char>(mousePos.y);

    wxMilliSleep(3);

    mouse_byte_sequence.push_back(x_byte);
    mouse_byte_sequence.push_back(y_byte);

    progress_entropy->SetValue(static_cast<int>(mouse_byte_sequence.size()));

    if (mouse_byte_sequence.size() >= 2048) {

        if (encrypt.CheckRandomnessQuality(mouse_byte_sequence)) {
            Close(true);
        }
        else {
            mouse_byte_sequence.clear();
            progress_entropy->SetValue(static_cast<int>(mouse_byte_sequence.size()));
        }
    }
}