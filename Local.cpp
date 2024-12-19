#include "Local.h"

bool LocalizationManager::LoadLanguage(const wxString& filePath)
{
    wxXmlDocument doc;
    if (!doc.Load(filePath))
    {
        return false;
    }

    wxXmlNode* root = doc.GetRoot();
    if (root->GetName() != "locale")
    {
        return false;
    }

    translations.clear();

    for (wxXmlNode* node = root->GetChildren(); node; node = node->GetNext())
    {
        if (node->GetType() == wxXML_ELEMENT_NODE && node->GetName() == "entry")
        {
            wxString id = node->GetAttribute("id", "");
            wxString text = node->GetNodeContent();
            translations[id] = text;
        }
    }

    return true;
}

wxString LocalizationManager::GetTranslation(const wxString& id) const
{
    auto it = translations.find(id);
    if (it != translations.end())
    {
        wxString result = it->second;

        if (result.length() > MAX_STRING_LENGTH)
        {
            result = result.substr(0, MAX_STRING_LENGTH);
        }

        return result;
    }
    return id;
}