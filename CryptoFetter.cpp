#include "CryptoFetter.h"
#include "EncryptFrame.h"
#include "Local.h"

wxIMPLEMENT_APP(Fetter);

bool Fetter::OnInit()
{
	EncryptFrame* mainFrame = new EncryptFrame("CryptoFetterX v. 1.0.0");

	mainFrame->SetClientSize(815, 550);
	mainFrame->SetSizeHints(815, 550, 815, 550);

	mainFrame->Center();
	mainFrame->Show();

	return true;
}