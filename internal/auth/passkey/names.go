package passkey

import (
	"encoding/hex"
	"strings"
)

// DefaultName is a new passkey's name when its authenticator is not known.
const DefaultName = "Passkey"

// aaguidNames names a few common passkey providers by AAGUID, so a new
// passkey gets a name the person recognises. It is a small hand-kept subset
// of the community list (passkeydeveloper/passkey-authenticator-aaguids);
// anything else is DefaultName and can be renamed.
var aaguidNames = map[string]string{
	"fbfc3007154e4ecc8c0b6e020557d7bd": "iCloud Keychain",
	"ea9b8d664d011d213ce4b6b48cb575d4": "Google Password Manager",
	"adce000235bcc60a648b0b25f1f05503": "Chrome on Mac",
	"08987058cadc4b81b6e130de50dcbe96": "Windows Hello",
	"9ddd1817af5a4672a2b93e3dd95000a9": "Windows Hello",
	"6028b017b1d44c02b4b3afcdafc96bb2": "Windows Hello",
	"bada5566a7aa401fbd9645619a55120d": "1Password",
	"d548826e79b4db40a3d811116f7e8349": "Bitwarden",
	"531126d6e717415c93203d9aa6981239": "Dashlane",
	"fdb141b25d84443e8a354698c205a502": "KeePassXC",
	"50726f746f6e5061737350726f746f6e": "Proton Pass",
	"53414d53554e47000000000000000000": "Samsung Pass",
}

// NameForAAGUID is the default name for a passkey from the authenticator
// model aaguid.
func NameForAAGUID(aaguid []byte) string {
	if n, ok := aaguidNames[strings.ToLower(hex.EncodeToString(aaguid))]; ok {
		return n
	}
	return DefaultName
}
