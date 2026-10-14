package dict

import "io"

func DumpSnapshotForTesting(s *Snapshot) []string   { return dumpSnapshot(s) }
func ParseXMLForTesting(r io.Reader) (*File, error) { return parseFile(r) }
func ParseFlagsForTesting(s string) (int, error)    { return parseFlags(s) }

const FlagMForTesting = flagM
const FlagVForTesting = flagV

func SourceNamesForTesting(dictionaries ...Dictionary) ([]string, error) {
	sources, err := dictionarySources(dictionaries)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(sources))
	for i, s := range sources {
		names[i] = s.name
	}
	return names, nil
}

type CodeIndexForTest struct{ AppID, Code, VendorID uint32 }
type NameIndexForTest struct {
	AppID uint32
	Name  string
}

func CodeIndexForTesting(s *Snapshot) map[CodeIndexForTest]*AVP {
	result := make(map[CodeIndexForTest]*AVP, len(s.avpcode))
	for k, v := range s.avpcode {
		result[CodeIndexForTest{k.appID, k.code, k.vendorID}] = v
	}
	return result
}
func NameIndexForTesting(s *Snapshot) map[NameIndexForTest]*AVP {
	result := make(map[NameIndexForTest]*AVP, len(s.avpname))
	for k, v := range s.avpname {
		result[NameIndexForTest{k.appID, k.name}] = v
	}
	return result
}
func RegistrationCountForTesting(s *Snapshot) int { return len(s.regs) }
func SnapshotFromFilesForTesting(files []*File) (*Snapshot, error) {
	return emptySnapshot.with(files, nil)
}
func SameAVPForTesting(a, b *AVP) bool { return sameAVP(a, b) }
