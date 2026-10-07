// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package diam

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"reflect"
	"strings"
	"time"

	"github.com/gomaja/go-diameter/diam/avp"
	"github.com/gomaja/go-diameter/diam/datatype"
	"github.com/gomaja/go-diameter/diam/dict"
)

// PrettyDump returns a human-readable, indented representation of the
// Message: header line, AVP column titles, and recursively formatted
// grouped AVPs. Intended for logs and debugging, not for parsing.
func (m *Message) PrettyDump() string {
	var b bytes.Buffer
	prettyDumpMessage(&b, m, 0)
	return b.String()
}

func prettyDumpMessage(w io.Writer, m *Message, depth int) {
	requestFlag, errorFlag, proxyFlag, retransmittedFlag := flagsToString(m.Header)

	prettyFprintf(w, "%s(%d) %s(%d) %s%s%s%s %d, %d\n",
		cmdToString(m.Dictionary(), m.Header),
		m.Header.CommandCode,
		appIdToString(int(m.Header.ApplicationID)),
		m.Header.ApplicationID,
		requestFlag,
		errorFlag,
		proxyFlag,
		retransmittedFlag,
		m.Header.HopByHopID,
		m.Header.EndToEndID)

	prettyFprintf(w, "  %-40s %8s %5s  %s %s %s  %-18s  %s\n",
		"AVP", "Vendor", "Code", "V", "M", "P", "Type", "Value")

	for _, a := range m.AVP {
		prettyDumpAVP(w, m, a, depth)
	}
}

func prettyDumpGroupedAVP(w io.Writer, m *Message, a *AVP, depth int) {
	group, ok := a.Data.(*GroupedAVP)
	if !ok || group == nil {
		return
	}
	for _, ga := range group.AVP {
		prettyDumpAVP(w, m, ga, depth)
	}
}

func prettyDumpAVP(w io.Writer, m *Message, a *AVP, depth int) {
	if a == nil {
		prettyFprintf(w, "  <nil AVP>\n")
		return
	}
	indent := strings.Repeat("  ", max(0, depth))

	avpName, avpType, avpData, isGrouped := avpToString(m, a)

	prettyFprintf(w, "  %-40s %8d %5d  %s %s %s  %-18s  %s\n",
		indent+avpName,
		a.VendorID,
		a.Code,
		boolToSymbol(a.Flags&avp.Vbit == avp.Vbit),
		boolToSymbol(a.Flags&avp.Mbit == avp.Mbit),
		boolToSymbol(a.Flags&avp.Pbit == avp.Pbit),
		avpType,
		avpData)

	if isGrouped {
		prettyDumpGroupedAVP(w, m, a, depth+1)
	}
}

func prettyFprintf(w io.Writer, format string, args ...interface{}) {
	if _, err := fmt.Fprintf(w, format, args...); err != nil {
		panic(err)
	}
}

func cmdToString(dictionary *dict.Parser, header *Header) string {
	if dictCMD, err := dictionary.FindCommand(
		header.ApplicationID,
		header.CommandCode,
	); err != nil {
		return "Unknown"
	} else {
		return dictCMD.Name
	}
}

func appIdToString(appId int) string {
	switch appId {
	case BASE_APP_ID:
		return "Common"
	case NETWORK_ACCESS_APP_ID:
		return "Network-Access"
	case BASE_ACCOUNTING_APP_ID:
		return "Accounting"
	case CHARGING_CONTROL_APP_ID:
		return "Charging-Control"
	case GX_CHARGING_CONTROL_APP_ID:
		return "Gx"
	case TGPP_S6A_APP_ID:
		return "S6A"
	case TGPP_SWX_APP_ID:
		return "SWX"
	case DIAMETER_SY_APP_ID:
		return "Sy"
	default:
		return "Unknown"
	}
}

func flagsToString(header *Header) (string, string, string, string) {
	var requestFlag string
	if header.CommandFlags&RequestFlag == RequestFlag {
		requestFlag = "request"
	} else {
		requestFlag = "answer"
	}

	var errorFlag string
	if header.CommandFlags&ErrorFlag == ErrorFlag {
		errorFlag = "error"
	} else {
		errorFlag = ""
	}

	var proxyFlag string
	if header.CommandFlags&ProxiableFlag == ProxiableFlag {
		proxyFlag = "proxiable"
	} else {
		proxyFlag = ""
	}

	var retransmittedFlag string
	if header.CommandFlags&RetransmittedFlag == RetransmittedFlag {
		retransmittedFlag = "retransmitted"
	} else {
		retransmittedFlag = ""
	}

	return requestFlag, errorFlag, proxyFlag, retransmittedFlag
}

func avpToString(m *Message, a *AVP) (string, string, string, bool) {

	var avpName string
	var avpType string
	var avpData string
	var isGrouped bool

	if dictAVP, err := m.Dictionary().FindAVP(
		m.Header.ApplicationID,
		a.Code,
		a.VendorID,
	); err != nil {
		avpName = "Unknown"
		avpType = "Unknown"
		avpData = fmt.Sprint(a.Data)
		isGrouped = false
	} else if group, ok := a.Data.(*GroupedAVP); ok && group != nil {
		avpName = dictAVP.Name
		avpType = "Grouped"
		avpData = ""
		isGrouped = true
	} else {
		if a.Data == nil || (reflect.ValueOf(a.Data).Kind() == reflect.Pointer && reflect.ValueOf(a.Data).IsNil()) {
			return dictAVP.Name, "Unknown", "<nil>", false
		}
		for k, v := range datatype.Available {
			if v == a.Data.Type() {
				avpType = k
				break
			}
		}
		avpName = dictAVP.Name
		avpData = dataValueToString(a.Data)
		isGrouped = false
	}

	return avpName, avpType, avpData, isGrouped
}

func dataValueToString(data datatype.Type) string {

	switch data := data.(type) {
	case datatype.Integer32, datatype.Integer64, datatype.Unsigned32, datatype.Unsigned64, datatype.Enumerated:
		return fmt.Sprintf("%d", data)
	case datatype.Float32, datatype.Float64:
		return fmt.Sprintf("%0.4f", data)
	case datatype.OctetString:
		return string(data)
	case datatype.UTF8String:
		return string(data)
	case datatype.DiameterIdentity:
		return string(data)
	case datatype.DiameterURI:
		return string(data)
	case datatype.IPFilterRule:
		return string(data)
	case datatype.QoSFilterRule:
		return string(data)
	case datatype.Time:
		return time.Time(data).String()
	case datatype.Address:
		if ip, ok := data.IP(); ok {
			return ip.String()
		}
		return data.String()
	case *datatype.Address:
		if data != nil {
			return dataValueToString(*data)
		}
	case datatype.IPv4:
		return net.IP(data).String()
	case datatype.IPv6:
		return net.IP(data).String()
	}

	return fmt.Sprint(data)
}

func boolToSymbol(flag bool) string {
	if flag {
		return "\u2713" // ✓
	}
	return "\u2717" // ✗
}

func max(x, y int) int {
	if x > y {
		return x
	}
	return y
}
