#ifndef LOCALIZATION_MANAGER_H
#define LOCALIZATION_MANAGER_H

#include <wx/wx.h>
#include <wx/xml/xml.h>
#include <map>

class LocalizationManager
{
public:

    LocalizationManager() = default;
    ~LocalizationManager() = default;

    bool LoadLanguage(const wxString& filePath);

    wxString GetTranslation(const wxString& id) const;

private:
    const size_t MAX_STRING_LENGTH = 1024;

    // id -> translate
    std::map<wxString, wxString> translations;
};

#endif
