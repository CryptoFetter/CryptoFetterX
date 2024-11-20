#include "CryptoFetter.h"
#include "EncryptFrame.h"
#include "Local.h"

wxIMPLEMENT_APP(Fetter);

bool Fetter::OnInit()
{
	EncryptFrame* mainFrame = new EncryptFrame("CryptoFetter v. 0.9.9");

	mainFrame->SetClientSize(815, 550);
	mainFrame->SetSizeHints(815, 550, 815, 550);

	mainFrame->Center();
	mainFrame->Show();

	return true;
}