The S6a/S13 fixtures were machine extracted from the specification documents,
with AVP names normalized to the dictionary's established spelling. They are
independent inputs to the tests, not generated from the bundled XML.

- `s6a_enums_spec.json`: 54 Enumerated AVPs and 280 named values from
  TS 29.272 V19.6.0, with reused values from TS 29.212 V20.0.0,
  TS 32.299 V19.0.0 and TS 32.422 V20.3.0. Each entry records its clause.
- `s6a_grouped_spec.json`: 61 Grouped AVP grammars from TS 29.272 V19.6.0,
  including its S6a/S6d-specific definitions of reused AVPs. Each entry records
  its clause and ordered member rules.

The tests check exact codes, normalized enum labels, rule order, fixed position,
and cardinality. RAT-dependent Report-Interval labels are checked by code;
TS 32.422 V20.3.0 §5.10.5 assigns different durations for different RATs.
The base overload/load definitions are pinned separately by
`overload_spec_test.go`, and the S6a overrides by `s6a_rfc_spec_test.go`.

`gx_spec.json` covers TS 29.212 V20.0.0 (2026-09): all 130 AVPs in
Table 5.3.0.1, 40 Enumerated registries (235 values), 30 Grouped grammars,
the 70 reused AVPs in Table 5.4.0.1, and CCR/CCA/RAR/RAA in §§5.6.2–5.6.5.
The reused table is numbered 5.4.0.1 in this version, not 5.3.0.2.
The four command bodies have 88, 51, 31 and 30 ordered rules respectively.

The document was downloaded from the [3GPP archive](https://www.3gpp.org/ftp/Specs/archive/29_series/29.212/29212-k00.zip)
and its version cross-checked against the [3GPP portal](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1672).
The archive SHA-256 is `2a18b6817f72e7f52961e939142497e1cd5ec0c90f52a2057c57374ea5a00958`;
the enclosed `29212-K00.docx` SHA-256 is
`5711cb649ab840050492caec9b9983009ba6774a3f326967e9305ee40cb5fbbb`.

The extraction tooling is not part of the repository. It reads each
document's Word XML directly, never the dictionary XML. Source-table metadata
for the reused AVPs comes from TS 29.214 V20.0.0, TS 29.061 V20.1.0, TS 29.229 V19.1.0,
TS 29.272 V19.6.0, TS 29.273 V19.2.0, TS 32.299 V19.0.0,
and the existing RFC 8506 source-table fixture. The 3GPP archive listings were
checked for these versions during the refresh. Seven RFC rows and two ETSI
ES 283 034 V2.2.0 rows are explicit transcriptions from their defining tables
or clauses; the 3GPP2-BSID identity is extracted from the primary 3GPP2
assigned-number registry. Each reused metadata entry identifies its source.
3GPP2-BSID's defining X.S0057-B encoding was not independently re-extracted;
the existing encoding is retained, with the Gx M-bit override tested.

Normalization and specification inconsistencies are explicit:

- `3GPP-` names use the established `TGPP-` spelling where applicable;
  hyphenation, case and enum typography are normalized for comparison.
- Table 5.3.0.1 misspells `Enumerated` as `Enumarated` for
  Usage-Monitoring-Level; §5.3.61 supplies the correct type.
- Default-Access imports the complete IP-CAN-Type enumeration by reference
  in §5.3.120; the clause restricts applicable values separately.
- Max-PLR-DL/UL use Unsigned32, in tenths of percent over 0..1000, as
  §§5.3.138–139 specify. CR 1665r2 (CP-181017, CT#80), incorporated in
  V15.3.0, replaced Float32 following RAN3 INTEGER(0..1000). The CR changed
  these clauses but not Table 5.3.0.1; that table still contains the old type.
- §5.3.36 prints `2 [ Tunnel-Header-Filter ]`: two repetitions of an
  optional element, hence 0..2 occurrences under RFC 5234 §§3.7–3.8
  (updated by RFC 7405). This agrees with the length-only prose. The
  fixture retains the original `abnf` string.
- Table 5.3.0.1 prints `M.V` for QoS-Upgrade and Rule-Failure-Code;
  the fixture normalizes this punctuation typo to the flag set `M,V`.
  Malformed flag strings are rejected by the dictionary loader.
- Event-Trigger 36 uses `USER_CSG_HYBRID_UNSUBSCRIBED_INFORMATION_CHANGE`,
  the spelling in Table 5b.4.0.1, without the stray space in §5.3.7.
- TS 29.214's table points PC-Session-Recovery-Status to nonexistent
  §5.3.142. Its actual definition is §5.3.81, used for the citation.

`gx_spec_test.go` compares flags, types, codes, enums, ordered members,
fixed positions, cardinalities and proxiability, and recursively checks the
Gx M-bit overrides for usage units and Trace-Data. `gx_wire_spec_test.go`
round-trips all 130 Gx AVPs, reused AVPs with source metadata, and every
Gx-local definition, including nested overrides (272 distinct AVPs).
It also exercises all four commands and cardinality/position/header boundaries.

`gx_copied_spec.json` pins 11 reused roots, 15 Grouped grammars and all
86 definitions in their named-member closure. They are extracted from the
TS 29.214 V20.0.0 and TS 29.229 V19.1.0 grammars, the TS 32.299 V19.0.0
grammars and metadata, the RFC 8581/8583 grammars and the existing
TS 29.272 V19.6.0 Grouped fixture, never from dictionary XML. RFC scalar
metadata and the usage-unit restriction from TS 29.212 Table 5.4.0.1 are
explicit transcriptions. The lowercase `v` for Event-Threshold-RSRQ in
TS 29.272 Table 7.3.1/1 is normalized to `V`. Each descendant has its source
metadata checked; each named member must itself have a fixture entry.

After extraction, the fixtures apply the CR-backed Max-PLR correction and the
flag and enum typography normalizations, and take all three values of
Required-Access-Info from TS 29.214 §5.3.34.

SourceID, Load-Type and Load-Value inherit their base definitions in Gx.
Load's wildcard rule adds `must-not="M"` under TS 29.212 V20.0.0
Table 5.4.0.1 to every member, including named members and extensions.
SourceID inside OC-Supported-Features and OC-OLR retains RFC 8581 §7.4 flags.
Member prohibitions allow only M/P, apply to outgoing messages, and are
rejected atomically when they contradict a resolved member's required flags.
Receive validation continues to accept understood M-bit AVPs.
RFC 8583 §§7.4–7.5 define SourceID's Load use and leave M policy to the
application. The M-set 3GPP VSA overrides cite TS 29.212 §5.4, rather than
attributing them to TS 29.061's table.

The regression tests cover Gx and Rx Callee-Information optionality,
Required-Access-Info value 2, Content-Version and Load-Value widths, exact
flag sets, XML flag rejection, SourceID parent scope, and recursive copied
metadata.

RFC Editor and Datatracker relationships and errata were
rechecked for RFCs 6733, 7075, 7405, 7683, 8506, 8553, 8581, 8583 and 5234.
The databases agree and errata dispositions are unchanged from the initial
audit; held/rejected proposals were not applied.
