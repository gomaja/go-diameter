package sm

import (
	"testing"

	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// RFC 6733 §5.3.6 advertises the suppliers of supported AVPs, including
// suppliers declared by dependencies of a selected application. RFC 7155
// and RFC 8506 add no vendor-specific AVPs. Pin every bundle's advertisement
// so changes in shared dictionaries cannot silently change capabilities.
func TestNASCCSupportedVendors(t *testing.T) {
	for _, bundle := range append(dict.AllBundled(), dict.Bundled("default")) {
		t.Run(string(bundle), func(t *testing.T) {
			dictionary := dict.Default
			if bundle != "default" {
				dictionary = dict.New(bundle)
			}
			settings := *serverSettings
			settings.Dict = dictionary
			settings.HostIPAddresses = []datatype.Address{localhostAddress}
			client := &Client{Handler: mustNew(&settings), Dict: dictionary}
			request, err := client.makeCER(settings.HostIPAddresses)
			if err != nil {
				t.Fatal(err)
			}
			got := readSMCapabilities(t, request, dictionary)
			want := []uint32{5535, 10415, 13019}
			switch bundle {
			case dict.Base, dict.NASREQ:
				want = nil
			case dict.Cx, dict.Sh:
				want = []uint32{10415, 13019}
			case dict.S13:
				want = []uint32{10415}
			}
			checkSMVendors(t, got.supported, want)
		})
	}
}
