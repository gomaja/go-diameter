package dict

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// TS 29.229 V19.1.0 Table 6.3.0.1 and TS 29.329 V19.1.0 Table 6.3.1.
// These expectations include reused AVPs through each application's lookup scope.
func TestCxShAVPTable(t *testing.T) {
	for _, tc := range []struct {
		app                     uint32
		name                    string
		code, vendor            uint32
		typ, must, may, mustNot string
	}{
		{16777216, "Visited-Network-Identifier", 600, 10415, "OctetString", "M,V", "", ""},
		{16777216, "Public-Identity", 601, 10415, "UTF8String", "M,V", "", ""},
		{16777216, "Server-Name", 602, 10415, "UTF8String", "M,V", "", ""},
		{16777216, "Server-Capabilities", 603, 10415, "Grouped", "M,V", "", ""},
		{16777216, "Mandatory-Capability", 604, 10415, "Unsigned32", "M,V", "", ""},
		{16777216, "Optional-Capability", 605, 10415, "Unsigned32", "M,V", "", ""},
		{16777216, "User-Data", 606, 10415, "OctetString", "M,V", "", ""},
		{16777216, "SIP-Number-Auth-Items", 607, 10415, "Unsigned32", "M,V", "", ""},
		{16777216, "SIP-Authentication-Scheme", 608, 10415, "UTF8String", "M,V", "", ""},
		{16777216, "SIP-Authenticate", 609, 10415, "OctetString", "M,V", "", ""},
		{16777216, "SIP-Authorization", 610, 10415, "OctetString", "M,V", "", ""},
		{16777216, "SIP-Authentication-Context", 611, 10415, "OctetString", "M,V", "", ""},
		{16777216, "SIP-Auth-Data-Item", 612, 10415, "Grouped", "M,V", "", ""},
		{16777216, "SIP-Item-Number", 613, 10415, "Unsigned32", "M,V", "", ""},
		{16777216, "Server-Assignment-Type", 614, 10415, "Enumerated", "M,V", "", ""},
		{16777216, "Deregistration-Reason", 615, 10415, "Grouped", "M,V", "", ""},
		{16777216, "Reason-Code", 616, 10415, "Enumerated", "M,V", "", ""},
		{16777216, "Reason-Info", 617, 10415, "UTF8String", "M,V", "", ""},
		{16777216, "Charging-Information", 618, 10415, "Grouped", "M,V", "", ""},
		{16777216, "Primary-Event-Charging-Function-Name", 619, 10415, "DiameterURI", "M,V", "", ""},
		{16777216, "Secondary-Event-Charging-Function-Name", 620, 10415, "DiameterURI", "M,V", "", ""},
		{16777216, "Primary-Charging-Collection-Function-Name", 621, 10415, "DiameterURI", "M,V", "", ""},
		{16777216, "Secondary-Charging-Collection-Function-Name", 622, 10415, "DiameterURI", "M,V", "", ""},
		{16777216, "User-Authorization-Type", 623, 10415, "Enumerated", "M,V", "", ""},
		{16777216, "User-Data-Already-Available", 624, 10415, "Enumerated", "M,V", "", ""},
		{16777216, "Confidentiality-Key", 625, 10415, "OctetString", "M,V", "", ""},
		{16777216, "Integrity-Key", 626, 10415, "OctetString", "M,V", "", ""},
		{16777216, "Supported-Features", 628, 10415, "Grouped", "V", "M", ""},
		{16777216, "Feature-List-ID", 629, 10415, "Unsigned32", "V", "", "M"},
		{16777216, "Feature-List", 630, 10415, "Unsigned32", "V", "", "M"},
		{16777216, "Supported-Applications", 631, 10415, "Grouped", "V", "", "M"},
		{16777216, "Associated-Identities", 632, 10415, "Grouped", "V", "", "M"},
		{16777216, "Originating-Request", 633, 10415, "Enumerated", "M,V", "", ""},
		{16777216, "Wildcarded-Public-Identity", 634, 10415, "UTF8String", "V", "", "M"},
		{16777216, "SIP-Digest-Authenticate", 635, 10415, "Grouped", "V", "", "M"},
		{16777216, "Digest-Realm", 104, 0, "UTF8String", "M", "", "V"},
		{16777216, "Digest-Algorithm", 111, 0, "UTF8String", "M", "", "V"},
		{16777216, "Digest-Qop", 110, 0, "UTF8String", "M", "", "V"},
		{16777216, "Digest-HA1", 121, 0, "UTF8String", "M", "", "V"},
		{16777216, "UAR-Flags", 637, 10415, "Unsigned32", "V", "", "M"},
		{16777216, "Loose-Route-Indication", 638, 10415, "Enumerated", "V", "", "M"},
		{16777216, "SCSCF-Restoration-Info", 639, 10415, "Grouped", "V", "", "M"},
		{16777216, "Path", 640, 10415, "OctetString", "V", "", "M"},
		{16777216, "Contact", 641, 10415, "OctetString", "V", "", "M"},
		{16777216, "Subscription-Info", 642, 10415, "Grouped", "V", "", "M"},
		{16777216, "Call-ID-SIP-Header", 643, 10415, "OctetString", "V", "", "M"},
		{16777216, "From-SIP-Header", 644, 10415, "OctetString", "V", "", "M"},
		{16777216, "To-SIP-Header", 645, 10415, "OctetString", "V", "", "M"},
		{16777216, "Record-Route", 646, 10415, "OctetString", "V", "", "M"},
		{16777216, "Associated-Registered-Identities", 647, 10415, "Grouped", "V", "", "M"},
		{16777216, "Multiple-Registration-Indication", 648, 10415, "Enumerated", "V", "", "M"},
		{16777216, "Restoration-Info", 649, 10415, "Grouped", "V", "", "M"},
		{16777216, "Session-Priority", 650, 10415, "Enumerated", "V", "", "M"},
		{16777216, "Identity-with-Emergency-Registration", 651, 10415, "Grouped", "V", "", "M"},
		{16777216, "Priviledged-Sender-Indication", 652, 10415, "Enumerated", "V", "", "M"},
		{16777216, "LIA-Flags", 653, 10415, "Unsigned32", "V", "", "M"},
		{16777216, "OC-Supported-Features", 621, 0, "Grouped", "", "", "M,V"},
		{16777216, "OC-OLR", 623, 0, "Grouped", "", "", "M,V"},
		{16777216, "Initial-CSeq-Sequence-Number", 654, 10415, "Unsigned32", "V", "", "M"},
		{16777216, "SAR-Flags", 655, 10415, "Unsigned32", "V", "", "M"},
		{16777216, "Allowed-WAF-WWSF-Identities", 656, 10415, "Grouped", "V", "", "M"},
		{16777216, "WebRTC-Authentication-Function-Name", 657, 10415, "UTF8String", "V", "", "M"},
		{16777216, "WebRTC-Web-Server-Function-Name", 658, 10415, "UTF8String", "V", "", "M"},
		{16777216, "DRMP", 301, 0, "Enumerated", "", "", "M,V"},
		{16777216, "Load", 650, 0, "Grouped", "", "", "M,V"},
		{16777216, "RTR-Flags", 659, 10415, "Unsigned32", "V", "", "M"},
		{16777216, "P-CSCF-Subscription-Info", 660, 10415, "Grouped", "V", "", "M"},
		{16777216, "Registration-Time-Out", 661, 10415, "Time", "V", "", "M"},
		{16777216, "Alternate-Digest-Algorithm", 662, 10415, "UTF8String", "V", "", "M"},
		{16777216, "Alternate-Digest-HA1", 663, 10415, "UTF8String", "V", "", "M"},
		{16777216, "Failed-PCSCF", 664, 10415, "Grouped", "V", "", "M"},
		{16777216, "PCSCF-FQDN", 665, 10415, "DiameterIdentity", "V", "", "M"},
		{16777216, "PCSCF-IP-Address", 666, 10415, "Address", "V", "", "M"},
		{16777216, "OC-Reg-Timer-Ext", 667, 10415, "Unsigned32", "V", "", "M"},
		{16777217, "User-Identity", 700, 10415, "Grouped", "M,V", "", ""},
		{16777217, "MSISDN", 701, 10415, "OctetString", "M,V", "", ""},
		{16777217, "User-Data", 702, 10415, "OctetString", "M,V", "", ""},
		{16777217, "Data-Reference", 703, 10415, "Enumerated", "M,V", "", ""},
		{16777217, "Service-Indication", 704, 10415, "OctetString", "M,V", "", ""},
		{16777217, "Subs-Req-Type", 705, 10415, "Enumerated", "M,V", "", ""},
		{16777217, "Requested-Domain", 706, 10415, "Enumerated", "M,V", "", ""},
		{16777217, "Current-Location", 707, 10415, "Enumerated", "M,V", "", ""},
		{16777217, "Identity-Set", 708, 10415, "Enumerated", "V", "", "M"},
		{16777217, "Expiry-Time", 709, 10415, "Time", "V", "", "M"},
		{16777217, "Send-Data-Indication", 710, 10415, "Enumerated", "V", "", "M"},
		{16777217, "Server-Name", 602, 10415, "UTF8String", "M,V", "", ""},
		{16777217, "Supported-Features", 628, 10415, "Grouped", "V", "M", ""},
		{16777217, "Feature-List-ID", 629, 10415, "Unsigned32", "V", "", "M"},
		{16777217, "Feature-List", 630, 10415, "Unsigned32", "V", "", "M"},
		{16777217, "Supported-Applications", 631, 10415, "Grouped", "V", "", "M"},
		{16777217, "Public-Identity", 601, 10415, "UTF8String", "M,V", "", ""},
		{16777217, "DSAI-Tag", 711, 10415, "OctetString", "M,V", "", ""},
		{16777217, "Wildcarded-Public-Identity", 634, 10415, "UTF8String", "V", "", "M"},
		{16777217, "Wildcarded-IMPU", 636, 10415, "UTF8String", "V", "", "M"},
		{16777217, "Session-Priority", 650, 10415, "Enumerated", "V", "", "M"},
		{16777217, "One-Time-Notification", 712, 10415, "Enumerated", "V", "", "M"},
		{16777217, "Requested-Nodes", 713, 10415, "Unsigned32", "V", "", "M"},
		{16777217, "Serving-Node-Indication", 714, 10415, "Enumerated", "V", "", "M"},
		{16777217, "Repository-Data-ID", 715, 10415, "Grouped", "V", "", "M"},
		{16777217, "Sequence-Number", 716, 10415, "Unsigned32", "V", "", "M"},
		{16777217, "Pre-paging-Supported", 717, 10415, "Enumerated", "V", "", "M"},
		{16777217, "Local-Time-Zone-Indication", 718, 10415, "Enumerated", "V", "", "M"},
		{16777217, "UDR-Flags", 719, 10415, "Unsigned32", "V", "", "M"},
		{16777217, "Call-Reference-Info", 720, 10415, "Grouped", "V", "", "M"},
		{16777217, "Call-Reference-Number", 721, 10415, "OctetString", "V", "", "M"},
		{16777217, "AS-Number", 722, 10415, "OctetString", "V", "", "M"},
		{16777217, "OC-Supported-Features", 621, 0, "Grouped", "", "", "M,V"},
		{16777217, "OC-OLR", 623, 0, "Grouped", "", "", "M,V"},
		{16777217, "DRMP", 301, 0, "Enumerated", "", "", "M,V"},
		{16777217, "Load", 650, 0, "Grouped", "", "", "M,V"},
		{16777216, "Line-Identifier", 500, 13019, "OctetString", "V", "", "M"},
		{16777216, "Wildcarded-IMPU", 636, 10415, "UTF8String", "V", "", "M"},
		// TS 29.329 V19.1.0 Table 6.3/2; TS 29.336 V20.0.0 §6.4.11.
		{16777217, "External-Identifier", 3111, 10415, "UTF8String", "M,V", "", ""},
	} {
		t.Run(fmt.Sprintf("%d/%s", tc.app, tc.name), func(t *testing.T) {
			byName, err := Default.FindAVPByName(tc.app, tc.name)
			if err != nil {
				t.Fatal(err)
			}
			byCode, err := Default.FindAVP(tc.app, tc.code, tc.vendor)
			if err != nil {
				t.Fatal(err)
			}
			if byName != byCode {
				t.Fatal("name and wire-code lookups disagree")
			}
			mayEncrypt := "N"
			if tc.name == "Line-Identifier" {
				// ETSI ES 283 035 V3.2.1 Table 4.
				mayEncrypt = "Y"
			}
			if byName.Code != tc.code || byName.VendorID != tc.vendor || byName.Data.TypeName != tc.typ || byName.Must != tc.must || byName.May != tc.may || byName.MustNot != tc.mustNot || byName.MayEncrypt != mayEncrypt {
				t.Fatalf("AVP = %#v, expected %+v", byName, tc)
			}
		})
	}
}

// TS 29.229 V19.1.0 §§6.1.1-12; TS 29.329 V19.1.0 §§6.1.1-8.
// Each row transcribes the ordered CCF. ! is fixed 1, + is 1+, * is 0+,
// ? is 0..1, and an unmarked name is exactly 1.
func TestCxShCommandCCF(t *testing.T) {
	for _, tc := range []struct {
		app, code uint32
		request   bool
		ccf       string
	}{
		{16777216, 300, true, "!Session-Id ?DRMP Vendor-Specific-Application-Id Auth-Session-State Origin-Host Origin-Realm ?Destination-Host Destination-Realm User-Name ?OC-Supported-Features *Supported-Features Public-Identity Visited-Network-Identifier ?User-Authorization-Type ?UAR-Flags *AVP *Proxy-Info *Route-Record"},
		{16777216, 300, false, "!Session-Id ?DRMP Vendor-Specific-Application-Id ?Result-Code ?Experimental-Result Auth-Session-State Origin-Host Origin-Realm ?OC-Supported-Features ?OC-OLR *Load *Supported-Features ?Server-Name ?Server-Capabilities *AVP ?Failed-AVP *Proxy-Info *Route-Record"},
		{16777216, 301, true, "!Session-Id ?DRMP Vendor-Specific-Application-Id Auth-Session-State Origin-Host Origin-Realm ?Destination-Host Destination-Realm ?User-Name ?OC-Supported-Features *Supported-Features *Public-Identity ?Wildcarded-Public-Identity Server-Name Server-Assignment-Type User-Data-Already-Available ?SCSCF-Restoration-Info ?Multiple-Registration-Indication ?Session-Priority ?SAR-Flags ?Failed-PCSCF *AVP *Proxy-Info *Route-Record"},
		{16777216, 301, false, "!Session-Id ?DRMP Vendor-Specific-Application-Id ?Result-Code ?Experimental-Result Auth-Session-State Origin-Host Origin-Realm ?User-Name ?OC-Supported-Features ?OC-OLR *Load *Supported-Features ?User-Data ?Charging-Information ?Associated-Identities ?Loose-Route-Indication *SCSCF-Restoration-Info ?Associated-Registered-Identities ?Server-Name ?Wildcarded-Public-Identity ?Priviledged-Sender-Indication ?Allowed-WAF-WWSF-Identities *AVP ?Failed-AVP *Proxy-Info *Route-Record"},
		{16777216, 302, true, "!Session-Id ?DRMP Vendor-Specific-Application-Id Auth-Session-State Origin-Host Origin-Realm ?Destination-Host Destination-Realm ?Originating-Request ?OC-Supported-Features *Supported-Features Public-Identity ?User-Authorization-Type ?Session-Priority *AVP *Proxy-Info *Route-Record"},
		{16777216, 302, false, "!Session-Id ?DRMP Vendor-Specific-Application-Id ?Result-Code ?Experimental-Result Auth-Session-State Origin-Host Origin-Realm ?OC-Supported-Features ?OC-OLR *Load *Supported-Features ?Server-Name ?Server-Capabilities ?Wildcarded-Public-Identity ?LIA-Flags *AVP ?Failed-AVP *Proxy-Info *Route-Record"},
		{16777216, 303, true, "!Session-Id ?DRMP Vendor-Specific-Application-Id Auth-Session-State Origin-Host Origin-Realm Destination-Realm ?Destination-Host User-Name ?OC-Supported-Features *Supported-Features Public-Identity SIP-Auth-Data-Item SIP-Number-Auth-Items Server-Name *AVP *Proxy-Info *Route-Record"},
		{16777216, 303, false, "!Session-Id ?DRMP Vendor-Specific-Application-Id ?Result-Code ?Experimental-Result Auth-Session-State Origin-Host Origin-Realm ?User-Name ?OC-Supported-Features ?OC-OLR *Load *Supported-Features ?Public-Identity ?SIP-Number-Auth-Items *SIP-Auth-Data-Item *AVP ?Failed-AVP *Proxy-Info *Route-Record"},
		{16777216, 304, true, "!Session-Id ?DRMP Vendor-Specific-Application-Id Auth-Session-State Origin-Host Origin-Realm Destination-Host Destination-Realm User-Name ?Associated-Identities *Supported-Features *Public-Identity Deregistration-Reason ?RTR-Flags *AVP *Proxy-Info *Route-Record"},
		{16777216, 304, false, "!Session-Id ?DRMP Vendor-Specific-Application-Id ?Result-Code ?Experimental-Result Auth-Session-State Origin-Host Origin-Realm ?Associated-Identities *Supported-Features *Identity-with-Emergency-Registration *AVP ?Failed-AVP *Proxy-Info *Route-Record"},
		{16777216, 305, true, "!Session-Id ?DRMP Vendor-Specific-Application-Id Auth-Session-State Origin-Host Origin-Realm Destination-Host Destination-Realm User-Name *Supported-Features ?User-Data ?Charging-Information ?SIP-Auth-Data-Item ?Allowed-WAF-WWSF-Identities *AVP *Proxy-Info *Route-Record"},
		{16777216, 305, false, "!Session-Id ?DRMP Vendor-Specific-Application-Id ?Result-Code ?Experimental-Result Auth-Session-State Origin-Host Origin-Realm *Supported-Features *AVP ?Failed-AVP *Proxy-Info *Route-Record"},
		{16777217, 306, true, "!Session-Id ?DRMP Vendor-Specific-Application-Id Auth-Session-State Origin-Host Origin-Realm ?Destination-Host Destination-Realm *Supported-Features User-Identity ?Wildcarded-Public-Identity ?Wildcarded-IMPU ?Server-Name *Service-Indication +Data-Reference *Identity-Set ?Requested-Domain ?Current-Location *DSAI-Tag ?Session-Priority ?User-Name ?Requested-Nodes ?Serving-Node-Indication ?Pre-paging-Supported ?Local-Time-Zone-Indication ?UDR-Flags ?Call-Reference-Info ?OC-Supported-Features *AVP *Proxy-Info *Route-Record"},
		{16777217, 306, false, "!Session-Id ?DRMP Vendor-Specific-Application-Id ?Result-Code ?Experimental-Result Auth-Session-State Origin-Host Origin-Realm *Supported-Features ?Wildcarded-Public-Identity ?Wildcarded-IMPU ?User-Data ?OC-Supported-Features ?OC-OLR *Load *AVP ?Failed-AVP *Proxy-Info *Route-Record"},
		{16777217, 307, true, "!Session-Id ?DRMP Vendor-Specific-Application-Id Auth-Session-State Origin-Host Origin-Realm ?Destination-Host Destination-Realm *Supported-Features User-Identity ?Wildcarded-Public-Identity ?Wildcarded-IMPU ?User-Name +Data-Reference User-Data ?OC-Supported-Features *AVP *Proxy-Info *Route-Record"},
		{16777217, 307, false, "!Session-Id ?DRMP Vendor-Specific-Application-Id ?Result-Code ?Experimental-Result Auth-Session-State Origin-Host Origin-Realm ?Wildcarded-Public-Identity ?Wildcarded-IMPU ?Repository-Data-ID ?Data-Reference *Supported-Features ?OC-Supported-Features ?OC-OLR *Load *AVP ?Failed-AVP *Proxy-Info *Route-Record"},
		{16777217, 308, true, "!Session-Id ?DRMP Vendor-Specific-Application-Id Auth-Session-State Origin-Host Origin-Realm ?Destination-Host Destination-Realm *Supported-Features User-Identity ?Wildcarded-Public-Identity ?Wildcarded-IMPU *Service-Indication ?Send-Data-Indication ?Server-Name Subs-Req-Type +Data-Reference *Identity-Set ?Expiry-Time *DSAI-Tag ?One-Time-Notification ?User-Name ?OC-Supported-Features *AVP *Proxy-Info *Route-Record"},
		{16777217, 308, false, "!Session-Id ?DRMP Vendor-Specific-Application-Id Auth-Session-State ?Result-Code ?Experimental-Result Origin-Host Origin-Realm ?Wildcarded-Public-Identity ?Wildcarded-IMPU *Supported-Features ?User-Data ?Expiry-Time ?OC-Supported-Features ?OC-OLR *Load *AVP ?Failed-AVP *Proxy-Info *Route-Record"},
		{16777217, 309, true, "!Session-Id ?DRMP Vendor-Specific-Application-Id Auth-Session-State Origin-Host Origin-Realm Destination-Host Destination-Realm *Supported-Features User-Identity ?Wildcarded-Public-Identity ?Wildcarded-IMPU ?User-Name User-Data *AVP *Proxy-Info *Route-Record"},
		{16777217, 309, false, "!Session-Id ?DRMP Vendor-Specific-Application-Id ?Result-Code ?Experimental-Result Auth-Session-State Origin-Host Origin-Realm *Supported-Features *AVP ?Failed-AVP *Proxy-Info *Route-Record"},
	} {
		t.Run(fmt.Sprintf("%d/%d/%t", tc.app, tc.code, tc.request), func(t *testing.T) {
			cmd, err := Default.FindCommand(tc.app, tc.code)
			if err != nil {
				t.Fatal(err)
			}
			side := cmd.Answer
			if tc.request {
				side = cmd.Request
			}
			checkCxShCCF(t, side.Rule, tc.ccf)
		})
	}
}

func checkCxShCCF(t *testing.T, got []*Rule, ccf string) {
	t.Helper()
	tokens := strings.Fields(ccf)
	if len(got) != len(tokens) {
		t.Fatalf("rule count %d, want %d: %s", len(got), len(tokens), ccf)
	}
	for i, token := range tokens {
		name, min, max, fixed := token, 1, 1, false
		switch token[0] {
		case '!':
			name, fixed = token[1:], true
		case '+':
			name, max = token[1:], 0
		case '*':
			name, min, max = token[1:], 0, 0
		case '?':
			name, min = token[1:], 0
		}
		r := got[i]
		effectiveMin := r.Min
		if r.Required && effectiveMin == 0 {
			effectiveMin = 1
		}
		if r.AVP != name || effectiveMin != min || r.Required != (min > 0) || r.Max != max || r.MaxSet != (max == 1) || r.Fixed != fixed {
			t.Errorf("rule %d = %+v, want %s", i, r, token)
		}
	}
}

// Enumerated values from TS 29.229 V19.1.0 §6.3 and TS 29.329 V19.1.0 §6.3.
func TestCxShEnumerations(t *testing.T) {
	for _, tc := range []struct {
		app          uint32
		name, values string
	}{
		{16777216, "Server-Assignment-Type", "0=NO_ASSIGNMENT 1=REGISTRATION 2=RE_REGISTRATION 3=UNREGISTERED_USER 4=TIMEOUT_DEREGISTRATION 5=USER_DEREGISTRATION 6=TIMEOUT_DEREGISTRATION_STORE_SERVER_NAME 7=USER_DEREGISTRATION_STORE_SERVER_NAME 8=ADMINISTRATIVE_DEREGISTRATION 9=AUTHENTICATION_FAILURE 10=AUTHENTICATION_TIMEOUT 11=DEREGISTRATION_TOO_MUCH_DATA 12=AAA_USER_DATA_REQUEST 13=PGW_UPDATE 14=RESTORATION"},
		{16777216, "Reason-Code", "0=PERMANENT_TERMINATION 1=NEW_SERVER_ASSIGNED 2=SERVER_CHANGE 3=REMOVE_S-CSCF"},
		{16777216, "User-Authorization-Type", "0=REGISTRATION 1=DE_REGISTRATION 2=REGISTRATION_AND_CAPABILITIES"},
		{16777216, "User-Data-Already-Available", "0=USER_DATA_NOT_AVAILABLE 1=USER_DATA_ALREADY_AVAILABLE"},
		{16777216, "Originating-Request", "0=ORIGINATING"},
		{16777216, "Loose-Route-Indication", "0=LOOSE_ROUTE_NOT_REQUIRED 1=LOOSE_ROUTE_REQUIRED"},
		{16777216, "Multiple-Registration-Indication", "0=NOT_MULTIPLE_REGISTRATION 1=MULTIPLE_REGISTRATION"},
		{16777216, "Session-Priority", "0=PRIORITY-0 1=PRIORITY-1 2=PRIORITY-2 3=PRIORITY-3 4=PRIORITY-4"},
		{16777216, "Priviledged-Sender-Indication", "0=NOT_PRIVILEDGED_SENDER 1=PRIVILEDGED_SENDER"},
		// RFC 7944 §9.1, RFC 7683 §7.6 as updated by RFC 8581 §7.2.1,
		// and RFC 8583 §7.2 define the reused IETF enumerations.
		{16777216, "DRMP", "0=PRIORITY_0 1=PRIORITY_1 2=PRIORITY_2 3=PRIORITY_3 4=PRIORITY_4 5=PRIORITY_5 6=PRIORITY_6 7=PRIORITY_7 8=PRIORITY_8 9=PRIORITY_9 10=PRIORITY_10 11=PRIORITY_11 12=PRIORITY_12 13=PRIORITY_13 14=PRIORITY_14 15=PRIORITY_15"},
		{16777216, "OC-Report-Type", "0=HOST_REPORT 1=REALM_REPORT 2=PEER_REPORT"},
		{16777216, "Load-Type", "0=HOST 1=PEER"},
		{16777217, "Data-Reference", "0=RepositoryData 10=IMSPublicIdentity 11=IMSUserState 12=S-CSCFName 13=InitialFilterCriteria 14=LocationInformation 15=UserState 16=ChargingInformation 17=MSISDN 18=PSIActivation 19=DSAI 21=ServiceLevelTraceInfo 22=IPAddressSecureBindingInformation 23=ServicePriorityLevel 24=SMSRegistrationInfo 25=UEReachabilityForIP 26=TADSinformation 27=STN-SR 28=UE-SRVCC-Capability 29=ExtendedPriority 30=CSRN 31=ReferenceLocationInformation 32=IMSI 33=IMSPrivateUserIdentity 34=IMEISV 35=UE-5G-SRVCC-Capability 36=ASRegistrationInfo"},
		{16777217, "Subs-Req-Type", "0=Subscribe 1=Unsubscribe"},
		{16777217, "Requested-Domain", "0=CS-Domain 1=PS-Domain"},
		{16777217, "Current-Location", "0=DoNotNeedInitiateActiveLocationRetrieval 1=InitiateActiveLocationRetrieval"},
		{16777217, "Identity-Set", "0=ALL_IDENTITIES 1=REGISTERED_IDENTITIES 2=IMPLICIT_IDENTITIES 3=ALIAS_IDENTITIES"},
		{16777217, "Send-Data-Indication", "0=USER_DATA_NOT_REQUESTED 1=USER_DATA_REQUESTED"},
		{16777217, "One-Time-Notification", "0=ONE_TIME_NOTIFICATION_REQUESTED"},
		{16777217, "Serving-Node-Indication", "0=ONLY_SERVING_NODES_REQUIRED"},
		{16777217, "Pre-paging-Supported", "0=PREPAGING_NOT_SUPPORTED 1=PREPAGING_SUPPORTED"},
		{16777217, "Local-Time-Zone-Indication", "0=ONLY_LOCAL_TIME_ZONE_REQUESTED 1=LOCAL_TIME_ZONE_WITH_LOCATION_INFO_REQUESTED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := Default.FindAVPByName(tc.app, tc.name)
			if err != nil {
				t.Fatal(err)
			}
			if a.Data.TypeName != "Enumerated" {
				t.Fatalf("type = %s", a.Data.TypeName)
			}
			var want []Enum
			for _, s := range strings.Fields(tc.values) {
				pair := strings.SplitN(s, "=", 2)
				v, err := strconv.ParseInt(pair[0], 10, 32)
				if err != nil {
					t.Fatal(err)
				}
				want = append(want, Enum{Code: int32(v), Name: pair[1]})
			}
			var got []Enum
			for _, e := range a.Data.Enum {
				got = append(got, *e)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("enums = %v, want %v", got, want)
			}
		})
	}
}

// TS 29.229 V19.1.0 §6.3; TS 29.329 V19.1.0 §§6.3.1, 6.3.24, 6.3.29;
// RFC 7683 §§7.1, 7.3 as updated by RFC 8581 §§7.1-2; RFC 8583 §7.1.
func TestCxShGroupedCCF(t *testing.T) {
	for _, tc := range []struct {
		app       uint32
		name, ccf string
	}{
		{16777216, "Server-Capabilities", "*Mandatory-Capability *Optional-Capability *Server-Name *AVP"},
		{16777216, "SIP-Auth-Data-Item", "?SIP-Item-Number ?SIP-Authentication-Scheme ?SIP-Authenticate ?SIP-Authorization ?SIP-Authentication-Context ?Confidentiality-Key ?Integrity-Key ?SIP-Digest-Authenticate ?Framed-IP-Address ?Framed-IPv6-Prefix ?Framed-Interface-Id *Line-Identifier *AVP"},
		{16777216, "Deregistration-Reason", "Reason-Code ?Reason-Info *AVP"},
		{16777216, "Charging-Information", "?Primary-Event-Charging-Function-Name ?Secondary-Event-Charging-Function-Name ?Primary-Charging-Collection-Function-Name ?Secondary-Charging-Collection-Function-Name *AVP"},
		{16777216, "Supported-Features", "Vendor-Id Feature-List-ID Feature-List *AVP"},
		{16777216, "Supported-Applications", "*Auth-Application-Id *Acct-Application-Id *Vendor-Specific-Application-Id *AVP"},
		{16777216, "Associated-Identities", "*User-Name *AVP"},
		{16777216, "SIP-Digest-Authenticate", "Digest-Realm ?Digest-Algorithm Digest-Qop Digest-HA1 ?Alternate-Digest-Algorithm ?Alternate-Digest-HA1 *AVP"},
		{16777216, "SCSCF-Restoration-Info", "User-Name +Restoration-Info ?Registration-Time-Out ?SIP-Authentication-Scheme *AVP"},
		{16777216, "Subscription-Info", "Call-ID-SIP-Header From-SIP-Header To-SIP-Header Record-Route Contact *AVP"},
		{16777216, "Associated-Registered-Identities", "*User-Name *AVP"},
		{16777216, "Restoration-Info", "Path Contact ?Initial-CSeq-Sequence-Number ?Call-ID-SIP-Header ?Subscription-Info ?P-CSCF-Subscription-Info *AVP"},
		{16777216, "Identity-with-Emergency-Registration", "User-Name Public-Identity *AVP"},
		{16777216, "Allowed-WAF-WWSF-Identities", "*WebRTC-Authentication-Function-Name *WebRTC-Web-Server-Function-Name *AVP"},
		{16777216, "P-CSCF-Subscription-Info", "Call-ID-SIP-Header From-SIP-Header To-SIP-Header Contact *AVP"},
		{16777216, "Failed-PCSCF", "?PCSCF-FQDN *PCSCF-IP-Address *AVP"},
		{16777216, "OC-Supported-Features", "?OC-Feature-Vector ?SourceID ?OC-Peer-Algo *AVP"},
		{16777216, "OC-OLR", "!OC-Sequence-Number !OC-Report-Type ?OC-Reduction-Percentage ?OC-Validity-Duration ?OC-Reg-Timer-Ext ?SourceID *AVP"},
		{16777216, "Load", "?Load-Type ?Load-Value ?SourceID *AVP"},
		{16777217, "User-Identity", "?Public-Identity ?MSISDN ?External-Identifier *AVP"},
		{16777217, "Repository-Data-ID", "Service-Indication Sequence-Number *AVP"},
		{16777217, "Call-Reference-Info", "Call-Reference-Number AS-Number *AVP"},
		{16777217, "OC-OLR", "!OC-Sequence-Number !OC-Report-Type ?OC-Reduction-Percentage ?OC-Validity-Duration ?SourceID *AVP"},
	} {
		t.Run(fmt.Sprintf("%d/%s", tc.app, tc.name), func(t *testing.T) {
			a, err := Default.FindAVPByName(tc.app, tc.name)
			if err != nil {
				t.Fatal(err)
			}
			if a.Data.TypeName != "Grouped" {
				t.Fatalf("type = %s", a.Data.TypeName)
			}
			checkCxShCCF(t, a.Data.Rule, tc.ccf)
		})
	}
}

func TestCxShInheritedAVPs(t *testing.T) {
	for _, app := range []uint32{16777216, 16777217} {
		for _, tc := range []struct {
			name string
			code uint32
			typ  string
		}{
			{"Framed-IP-Address", 8, "OctetString"}, {"Framed-IPv6-Prefix", 97, "OctetString"}, {"Framed-Interface-Id", 96, "Unsigned64"},
			{"Load-Value", 652, "Unsigned64"}, {"SourceID", 649, "DiameterIdentity"}, {"OC-Peer-Algo", 648, "Unsigned64"},
		} {
			d, err := Default.FindAVPByName(app, tc.name)
			if err != nil {
				t.Fatal(err)
			}
			if d.Code != tc.code || d.Data.TypeName != tc.typ || d.VendorID != 0 {
				t.Fatalf("%d/%s: %#v", app, tc.name, d)
			}
		}
	}
	// TS 29.229 §6.1.7 mandates Public-Identity on Cx, unlike TS 29.273 SWx.
	cx, err := Default.FindCommand(16777216, 303)
	if err != nil {
		t.Fatal(err)
	}
	swx, err := Default.FindCommand(16777265, 303)
	if err != nil {
		t.Fatal(err)
	}
	if cx == swx || cx.Short != "MA" || swx.Short != "MA" {
		t.Fatal("shared command code lost application scope")
	}
	cxHas, swxHas := false, false
	for _, r := range cx.Request.Rule {
		if r.AVP == "Public-Identity" && r.Required {
			cxHas = true
		}
	}
	for _, r := range swx.Request.Rule {
		if r.AVP == "Public-Identity" {
			swxHas = true
		}
	}
	if !cxHas || swxHas {
		t.Fatal("Cx and SWx MAR grammars conflated")
	}
	// TS 29.336 V20.0.0 Table 6.4.1/1 requires M,V, as does Sh.
	// Sh does not inherit S6c, whose application-specific definition forbids M.
	sh, err := Default.FindAVPByName(16777217, "External-Identifier")
	if err != nil {
		t.Fatal(err)
	}
	sms, err := Default.FindAVPByName(16777312, "External-Identifier")
	if err != nil {
		t.Fatal(err)
	}
	if sh.Must != "M,V" || sms.MustNot != "M" {
		t.Fatal("application M-bit override leaked")
	}
}
