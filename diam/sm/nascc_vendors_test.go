package sm

import (
	"testing"

	"github.com/gomaja/go-diameter/diam/datatype"
)

// RFC 6733 §5.3.6 advertises the suppliers of supported AVPs, including
// suppliers declared by dependencies of a selected application. RFC 7155
// and RFC 8506 add no vendor-specific AVPs. Pin every bundle's advertisement
// so changes in shared dictionaries cannot silently change capabilities.
func TestNASCCSupportedVendors(t *testing.T) {
	for _, bundle := range testDictionaryDescriptors() {
		t.Run(bundle.name, func(t *testing.T) {
			dictionary := newTestDictionary(bundle.dictionary)
			settings := *serverSettings
			settings.Dict = dictionary
			settings.HostIPAddresses = []datatype.Address{localhostAddress}
			client := &Client{Handler: mustNew(&settings), Dict: dictionary}
			request, err := client.makeCER(settings.HostIPAddresses)
			if err != nil {
				t.Fatal(err)
			}
			got := readSMCapabilities(t, request, dictionary)
			want := []uint32{5535, 10415, 13019, 45687}
			switch bundle.name {
			case "base", "nasreq":
				want = nil
			case "cx", "sh":
				want = []uint32{10415, 13019}
			case "s13":
				want = []uint32{10415}
			}
			checkSMVendors(t, got.supported, want)
		})
	}
}
