package cryptopro

import (
	"bytes"
	_ "embed"
	"encoding/xml"
	"fmt"
	"os"
	"testing"
)

//go:embed assets/large_xml.xml
var SampleLargeDoc string

const SampleSmallDoc = `
	<Person>
		<Name>
			<First>John</First>
			<Last>Doe</Last>
		</Name>
		<Age>30</Age>
		<Address>
			<City>New York</City>
			<State>NY</State>
			<ZipCode>10001</ZipCode>
		</Address>
		<Contact>
			<Email>john.doe@example.com</Email>
			<Phone>
				<Mobile>555-1234</Mobile>
				<Home>555-5678</Home>
			</Phone>
		</Contact>
	</Person>
`

type signatureSchema struct {
	Signature struct {
		SignedInfo struct {
			CanonicalizationMethod string
			SignatureMethod        string
			Reference              struct {
				Transforms struct {
					Transform []string
				}
				DigestMethod string
				DigestValue  string
			}
		}
		SignatureValue string `xml:"SignatureValue"`
		KeyInfo        any
	} `xml:"Signature"`
}

func TestSignXML(t *testing.T) {
	thumbprint, ok := os.LookupEnv("THUMBPRINT")
	if !ok {
		t.Error("no thumbprint provided")
		return
	}

	document := []byte(SampleSmallDoc)

	signedDocument, err := SignXML(document, thumbprint)
	if err != nil {
		t.Error("failed:", err)
		return
	}

	var structuredSignedDocument signatureSchema
	err = xml.NewDecoder(bytes.NewReader(signedDocument)).Decode(&structuredSignedDocument)
	if err != nil {
		t.Error("failed to decode the signed document:", err)
		return
	}

	fmt.Println(string(signedDocument))

	signature := structuredSignedDocument.Signature

	if signature.SignatureValue == "" {
		t.Error("signature value is empty")
		return
	}

	if signature.SignedInfo.Reference.DigestValue == "" {
		t.Error("digest value is empty")
	}
}

func BenchmarkSignSmallXml(b *testing.B) {
	thumbprint, ok := os.LookupEnv("THUMBPRINT")
	if !ok {
		b.Error("no thumbprint provided")
		return
	}

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := SignXML([]byte(SampleSmallDoc), thumbprint)
			if err != nil {
				b.Fatal("failed to sign:", err)
				return
			}
		}
	})
}

func BenchmarkSignLargeXml(b *testing.B) {
	thumbprint, ok := os.LookupEnv("THUMBPRINT")
	if !ok {
		b.Error("no thumbprint provided")
		return
	}

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := SignXML([]byte(SampleLargeDoc), thumbprint)
			if err != nil {
				b.Fatal("failed to sign:", err)
				return
			}
		}
	})
}
