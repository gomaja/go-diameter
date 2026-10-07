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

`rx_spec.json` covers TS 29.214 V20.0.0 (2026-09): all 84 Rx-specific
AVPs in Table 5.3.0.1, 17 Enumerated registries (78 values), 11 Grouped
grammars, all 39 reused AVPs in Table 5.4.0.1, and the eight command bodies
in §§5.6.1–5.6.8. The command bodies contain 42, 40, 41, 20, 15, 33, 13
and 16 ordered rules, respectively. The source is the
[3GPP archive](https://www.3gpp.org/ftp/Specs/archive/29_series/29.214/29214-k00.zip),
whose [version listing](https://www.3gpp.org/ftp/Specs/archive/29_series/29.214/)
identifies V20.0.0 as latest. The archive SHA-256 is
`639cbcba519539918c8965fdf6399307094b16d87306878d0ed588ac6335659c`;
the enclosed `29214-k00.docx` SHA-256 is
`4441ea316874d7a9f3adab68ea7b500b974b1f43b06110216f4a6d0622a439b3`.

The Rx-specific tables, enumerations, grouped grammars and command bodies
are extracted from the document's Word XML, independently of dictionary XML.
Reused metadata is taken from the independently extracted Gx and copied
source fixtures, the defining tables of TS 29.061 V20.1.0, TS 29.229 V19.1.0,
TS 29.273 V19.2.0 and TS 32.299 V19.0.0, and current RFC definitions.
The corresponding 3GPP archive listings were checked for these versions.
RFC 8506 §8 metadata and grouped grammars are extracted from its source
text and flag-table fixture; RFC 7683/8581 and 8583 supply overload and load
registries. RFC 7155 supplies the NASREQ definitions, and RFC 7944 the
DRMP registry. The additional primary-source transcriptions are
[TS 29.154 V19.0.0 Table 5.3.1.1 and §5.3.3](https://www.3gpp.org/ftp/Specs/archive/29_series/29.154/29154-j00.zip)
for Reference-Id and
[ETSI TS 183 017 V3.2.1 Table 7.3.1 and §7.3.9](https://www.etsi.org/deliver/etsi_TS/183000_183099/183017/03.02.01_60/ts_183017v030201p.pdf)
for Reservation-Priority. The latter uses vendor 13019, also confirmed by
the [ETSI AVP registry](https://portal.etsi.org/pnns/Protocol-Specification-Allocation/diameteravpcodeallocation).
No extraction tooling is included in the repository.

`rx_copied_spec.json` pins nine reused Grouped roots and all 34 definitions
in their named-member closure, including the nine grammars and four enum
registries. Their source clauses and original CCF are retained. Rx's usage
units are restricted to CC-Time and the three octet counters by Table 5.4.0.1;
the parent M bit is cleared, while members retain RFC 8506 flags. Unlike Gx,
Rx does not mandate clearing M on those members and does not add Monitoring-Time.
The usage units retain the RFC 8506 §§8.17/8.19 `*[ AVP ]` extension point.
The reused-member list restricts the named definitions; it does not prohibit
extensions. TS 29.214 §5.4.1, referring to TS 29.229 §7.1.1, permits new
optional AVPs with M cleared so older receivers can ignore them.
RFC 8506 §8.52's User-Equipment-Info-Extension grammar ends in `[ AVP ]`,
with a maximum of one extension. The source fixture pins this rule in
application 4 and all seven inheriting applications (Rx, Gx, S6a, SWx, Sy,
S6c and SGd); Rx inherits the common definition. The prose requirement to
include exactly one AVP is a sender rule that the dictionary grammar cannot
express. Wire tests cover one permitted extension and the cardinality error
for a second extension in application 4, Rx and Gx.
Load clears M on its parent and every member. Its wildcard rule's
`must-not="M"` applies to named members and extensions; SourceID elsewhere,
including the overload groups, retains RFC 8581 §7.4 flags.

Rx normalization and specification discrepancies:

- Names retain the established dictionary spelling, including `TGPP-`,
  `Framed-IPv6-Prefix`, `NetLoc-Access-Support` and `ToS-Traffic-Class`.
  Enumeration spaces, case and hyphenation are normalized for comparison.
  The stray space in `SPONSORED_DATA_CONNECTIVITY_ DISALLOWED` is removed.
- Media-Type OTHER's `0xFFFFFFFF` is represented as signed Enumerated `-1`
  under RFC 6733 §4.3.1. Specific-Action retains the two explicitly Void
  values (0 and 5); value 22 is not assigned by §5.3.13.
- Flag strings use `M,V` syntax and tests compare complete parsed flag sets.
  Blank encryption cells for Min-Desired-Bandwidth-DL/UL are preserved as
  unspecified, rather than inferred from neighboring rows.
- PC-Session-Recovery-Status is defined in §5.3.81. The table's nonexistent
  §5.3.142 reference traces to
  [Rx CR 1705r1 (C3-255458, CP-253038)](https://portal.3gpp.org/DesktopModules/CRs/CrDetails.aspx?CrId=591522),
  which listed §5.3.142 as its new clause. The fixture cites the published
  defining clause and does not change the enum values.
- Reused Max-PLR-DL/UL follow TS 29.212 V20.0.0 §§5.3.138–139, Unsigned32
  in tenths of a percent, rather than its stale Float32 table cells.
  [CR 1665r2 (CP-181017)](https://portal.3gpp.org/DesktopModules/CRs/CrDetails.aspx?CrId=297377)
  changed the defining clauses; TS 29.230 CR 0645r1 (CP-182073), approved
  in the [CR database](https://portal.3gpp.org/ChangeRequests.aspx?q=1&specnumber=29.230),
  also corrected the AVP registry to Unsigned32 in V15.4.0.
- Command fixed positions and PXY follow §5.6 and RFC 6733 §3.2 with
  Verified Erratum 4803's corrected `Diameter Header` literal.

The Rx tests compare the effective application 16777236 view from
`dict.Default`, including all source-pinned reused descendants, exact flags,
encryption where specified, enum values, ordered members, cardinalities,
fixed positions and P bits. The wire tests cover 148 distinct AVPs and all
eight commands, required/optional member boundaries, the two-Codec-Data
limit, and Load's parent-scoped M-bit rule. The RAT-Type regression checks
both the selected bundle with its dependencies and the full default view.

RFC Editor and Datatracker relationship records agree on the current
Diameter sources: RFC 6733 with 7075/8553, RFC 7155, RFC 8506, RFC 7683 with
8581, RFC 7944 and RFC 8583. Verified errata were reviewed; RFC 7683
Erratum 4549 concerns overload realm identification, while RFC 6733
Erratum 4803 directly affects the command grammar citation. Held/rejected
proposals were not applied: RFC 6733 Held 4210/4234/5084 and Rejected
4209/4462/4463/4473/4931/6833; RFC 3162 Held 3217 and Rejected 1923;
RFC 3264 Held 2098/2099 and Rejected 5177/7597; RFC 3605 Held 2292;
RFC 3959 Held 2050; RFC 5031 Held 1261/1262 and Rejected 6359.
DIME and MMUSIC are concluded; no replacement publication-queue document
was identified. Active RADEXT and AVTCORE documents do not replace the
Rx encodings audited here.

TS 29.214 still cites obsolete RFC 4005 (now RFC 7155), RFC 4566 and,
in an appendix with an incorrect `[17]` reference, RFC 2327 (now RFC 8866).
RFC 7155 changes NASREQ accounting, while Rx retains its own command CCF
and the reused framed-address encodings. The SDP replacement tightens
syntax; Codec-Data remains opaque OctetString data in this dictionary.

RFC 3162 is updated by [RFC 8044](https://www.rfc-editor.org/rfc/rfc8044.html),
which clarifies RADIUS data types. This has no dictionary impact:
Framed-IPv6-Prefix remains OctetString under RFC 7155 §4.4.10.5.6.
TS 32.299 V19.0.0 Table 7.2.0.1 has no encryption column; the four reused
party-address AVPs therefore leave encryption unspecified in Rx.
The Rx-only CER test pins Supported-Vendor-Id to 10415 and 13019.
