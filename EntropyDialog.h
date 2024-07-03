#ifndef ENTROPY_DIALOG_H
#define ENTROPY_DIALOG_H

#include <wx/wx.h>
#include "Crypto.h"

class EntropyDialog : public wxDialog
{
    Botan::secure_vector<uint8_t> mouse_byte_sequence;

    wxGauge* progress_entropy;

    void OnMouseEvent(wxMouseEvent& evt);

public:
    EntropyDialog(wxWindow* parent, wxWindowID id, const wxString& title);

    Botan::secure_vector<uint8_t> GetMouseEntropy() const {
        return mouse_byte_sequence;
    }
};

#endif