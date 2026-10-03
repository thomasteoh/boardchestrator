package idp

import (
	"strings"
	"testing"

	"github.com/thomasteoh/boardchestrator/internal/auth/samltest"
)

func TestParseSAMLAttrs(t *testing.T) {
	a, err := ParseSAMLAttrs(`{"subject":"employeeId","groups":"roles"}`)
	if err != nil || a.Subject != "employeeId" || a.Groups != "roles" {
		t.Fatalf("%+v %v", a, err)
	}
	if _, err := ParseSAMLAttrs(`{"picture":"x"}`); err == nil {
		t.Fatal("unknown key accepted")
	}
}

func TestParseIdPMetadata(t *testing.T) {
	ip := samltest.New(t)
	md, err := ParseIdPMetadata([]byte(ip.MetadataXML()))
	if err != nil || md.EntityID != ip.EntityID() {
		t.Fatalf("%v", err)
	}
	// Wrapped in an EntitiesDescriptor.
	inner := ip.MetadataXML()[strings.Index(ip.MetadataXML(), "<md:EntityDescriptor"):]
	wrapped := `<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">` + inner + `</md:EntitiesDescriptor>`
	if md, err := ParseIdPMetadata([]byte(wrapped)); err != nil || md.EntityID != ip.EntityID() {
		t.Fatalf("entities: %v", err)
	}
	for _, bad := range []string{
		"<x/>", "not xml",
		strings.Replace(ip.MetadataXML(), `use="signing"`, `use="encryption"`, 1),
		strings.Replace(ip.MetadataXML(), "HTTP-Redirect\" Location=\""+ip.SSOURL(), "HTTP-POST\" Location=\""+ip.SSOURL(), 1),
		strings.Replace(ip.MetadataXML(), `Location="`+ip.SSOURL()+`"`, `Location="javascript:alert(1)"`, 1),
	} {
		if _, err := ParseIdPMetadata([]byte(bad)); err == nil {
			t.Errorf("accepted bad metadata: %.80s", bad)
		}
	}
}

func TestValidateMetadataURL(t *testing.T) {
	for _, ok := range []string{"https://login.microsoftonline.com/t/federationmetadata/2007-06/federationmetadata.xml?appid=x", "http://127.0.0.1:8080/md"} {
		if err := ValidateMetadataURL(ok); err != nil {
			t.Errorf("%s: %v", ok, err)
		}
	}
	for _, bad := range []string{"http://idp.example/md", "ftp://x/y", "https://u:p@x/y", "/md", "https://x/y#f"} {
		if err := ValidateMetadataURL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestSPKeyPair(t *testing.T) {
	k, c, err := GenerateSPKeyPair("corp")
	if err != nil {
		t.Fatal(err)
	}
	key, cert, err := ParseSPKeyPair(k, c)
	if err != nil || key.N.BitLen() != 2048 || cert.NotAfter.Sub(cert.NotBefore).Hours() < 24*365*9 {
		t.Fatalf("key pair: %v", err)
	}
}
