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

`sy_spec.json` covers TS 29.219 V19.0.0 (2025-09): all seven AVPs in
Table 5.3.0.1, one Enumerated registry with two values, two Grouped grammars,
eight reused roots in Table 5.4, and all six command bodies in §§5.6.2–5.6.7.
The ordered rule counts are 18, 21, 14, 17, 13 and 17. The Sy entries and
command grammars were extracted directly from the specification's Word XML.
The [3GPP portal](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1679)
confirmed V19.0.0 as the latest version on 2026-10-07. The
[official archive](https://www.3gpp.org/ftp/Specs/archive/29_series/29.219/29219-j00.zip)
SHA-256 is `b02427f444861143f9622527ee997101de03cb548ec4b8f40c4cbc58aa0a94bc`;
the enclosed document SHA-256 is
`a478ed9a9d9986752d984cc4b3e704a27fb11d879af5fc5f482d4676fe431113`.

`sy_reused_spec.json` pins the eight reused roots and all 22 definitions in
their named-member closure, including five Grouped grammars. Shared source
extractions from the Gx fixtures were checked against the defining documents;
RFC 8506 §§8.46–8.48 and RFC enum registries were transcribed independently.
No fixture is derived from dictionary XML. Source citations distinguish the
original overload definitions from the RFC 8581 amendments. The
[TS 29.229 V19.1.0 archive](https://www.3gpp.org/ftp/Specs/archive/29_series/29.229/29229-j10.zip)
SHA-256 is `376b8793234f2f952a9f52a37771c56e51677e160160e5d48b1bf29585ac3b1e`;
its document SHA-256 is
`855ca97a19cb50a707fde220ce8ac043c2979200f0182aca3d4b530bd6a06c36`.
The [ETSI ES 283 034 V2.2.0 PDF](https://www.etsi.org/deliver/etsi_es/283000_283099/283034/02.02.00_60/es_283034v020200p.pdf)
SHA-256 is `e388719d1e6aea1b990bb8af5095348c7731f57ef7c14520902c3403aed7c35b`.
Both reused source versions were checked against their official publication
listings. Extraction tooling remains outside the repository.

Sy-specific interpretation and scope:

- Every Sy-specific AVP uses vendor 10415, including SL-Request-Type. The
  seven rows agree with their defining clauses; no table/clause correction
  or CR override is needed. Nonbreaking whitespace in CCF is normalized;
  M/P/V rules are compared as exact sets using comma-separated syntax.
- SN-Request-Type is an Unsigned32 bit mask, not an Enumerated AVP. Bits 0
  and 1 can be combined. Its M bit is forbidden.
- Load retains RFC 8583's extension point. Table 5.4 clears M on Load and
  every member, including extensions, through a wildcard member rule.
  SourceID retains its source definition outside Load.
- TS 29.229 §7.2.1 forbids M on Supported-Features in answers; Sy §5.1.6
  imports that rule, so the SLA member clears M. The initial SLR also
  clears M, but intermediate SLRs can set it. The initial-request condition
  depends on SL-Request-Type and cannot be represented by a static command
  rule; the caller must enforce it.
- Supported-Features and its children, Subscription-Id and its children,
  DRMP, and overload definitions inherit identical source definitions.
  ETSI vendor 13019 is declared for Logical-Access-ID and Physical-Access-ID,
  with 3GPP retained as the application author.
- Encryption metadata is compared only where the defining source supplies
  it. Sy Table 5.3.0.1 and the current RFC flag tables do not supply an
  encryption column; the fixture does not invent one.
- Tests compare `dict.Default`, including inheritance, and round-trip all
  29 Sy and reused definitions, all named grouped members, enum values,
  and all six commands. Command boundaries, Load member flags, feature
  flags and Sy's CER vendor advertisement have separate regressions.
- Value-dependent procedures remain outside dictionary validation: initial
  SLR identity/feature requirements, feature negotiation, result alternatives,
  pending-counter chronological ordering, and the §5.2 prohibition of
  Auth-Session-State through otherwise open command extension points.

The Sy specification retains obsolete references to RFCs 4005 (replaced by
7155), 4006 (8506), 5719 (6733), 2234 (via 4234 to 5234), and 4960 (9260).
Its §5.1.4 also mislabels RFC 791, the Internet Protocol specification, as
TCP; current TCP is RFC 9293. Current documents govern the new fixtures.
RFC Editor and Datatracker relationships, errata and relevant working-group
documents were cross-checked on 2026-10-07. RFC 6733 is updated by 7075/8553;
7683 by 8581; 5234 by 7405; and 3046 by 6607. RFC 7944, the DRMP source, has
no updates, obsoletes or errata. No database disagreement or
pending replacement for the dictionary RFCs was found. Verified RFC 6733
Erratum 4615 agrees with singleton Failed-AVP rules. Verified RFC 7683
Erratum 4549 concerns overload realm interpretation, not dictionary shape.
Held and rejected proposals were not applied: relevant held records include
RFC 6733 4210/4234/5084 and RFC 5234 2820/2914/6172/6173; rejected records
include RFC 6733 4209/4462/4463/4473/4931/6833, RFC 5234
1423/3096/4040/4564/5110/4361, and RFC 7405 5334. Reported RFC 7683
5277/5278 and RFC 6733 6832 remain unverified.


`s6c_spec.json` and `sgd_spec.json` cover TS 29.338 V19.3.0 (2025-09),
confirmed as the latest published version on the
[3GPP portal](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1714).
The
[source archive](https://www.3gpp.org/ftp/Specs/archive/29_series/29.338/29338-j30.zip)
SHA-256 is `d996894136580cf53f7451cb24ceffbcaa1c41bc985a078fe18724cc465160e0`;
the DOCX SHA-256 is
`abf8edd2b0aad6b279291f6436d1f10c2da10e003e799e79f398bbe808857226`.

The fixtures contain 33 S6c and 16 SGd specific AVPs, seven enumerations,
11 specific Grouped grammars, 24 and 13 reused table rows, and six and four
command bodies. S6c pins 109 effective definitions and SGd pins 112,
including 23 Grouped grammars and every named descendant, with inherited SMS
definitions included. Specific tables and grammars were extracted directly
from Word XML; reused source tables and grammars were extracted independently
or taken from the existing source-extracted S6a/Gx fixtures. RFC metadata is
an explicit transcription of the cited clauses. No specification expectations
were generated from bundled dictionary XML. Source typography is normalized
explicitly, including the stray space in `UE_ MEMORY_CAPACITY_EXCEEDED`,
`SGSN-Absent-User-Diagnostic SM`, `MME-Location Information`, and `Id`/`ID`.
The established `TGPP-AAA-Server-Name` spelling represents source
`3GPP-AAA-Server-Name`. Flags use exact comma-separated sets. SMS enum
labels are compared exactly after the documented stray-space correction in
the fixture; punctuation such as `SC-CONGESTION` is significant. Extraction
tooling is not distributed.

The recursively reused sources were checked against their current 3GPP portal
versions. Their archive hashes are:

| Document | Archive SHA-256 |
| --- | --- |
| [3GPP TS 29.329 V19.1.0](https://www.3gpp.org/ftp/Specs/archive/29_series/29.329/29329-j10.zip) | `4ca3f84834a42780785b09a6227b2755392d01bb61fa85c5ed347e2df298fd5c` |
| [3GPP TS 29.212 V20.0.0](https://www.3gpp.org/ftp/Specs/archive/29_series/29.212/29212-k00.zip) | `2a18b6817f72e7f52961e939142497e1cd5ec0c90f52a2057c57374ea5a00958` |
| [3GPP TS 29.173 V19.0.0](https://www.3gpp.org/ftp/Specs/archive/29_series/29.173/29173-j00.zip) | `8eee10735b41a304f5c2aca65a502dfa5f03607e9a545fff77e333f7bde895b3` |
| [3GPP TS 29.336 V20.0.0](https://www.3gpp.org/ftp/Specs/archive/29_series/29.336/29336-k00.zip) | `038bbadbcdc3a6715a06371f30aa31846cba37d4687f1379df1b0bdd29d044ac` |
| [3GPP TS 29.272 V19.6.0](https://www.3gpp.org/ftp/Specs/archive/29_series/29.272/29272-j60.zip) | `c40fd1834046f87655f4c7c1acd137b0f8f658a91f6cc83a215592ca8326a4b1` |
| [3GPP TS 29.229 V19.1.0](https://www.3gpp.org/ftp/Specs/archive/29_series/29.229/29229-j10.zip) | `376b8793234f2f952a9f52a37771c56e51677e160160e5d48b1bf29585ac3b1e` |
| [3GPP TS 29.217 V19.0.0](https://www.3gpp.org/ftp/Specs/archive/29_series/29.217/29217-j00.zip) | `801543a65e9405e401c389245d4d9cc6ac6e82af5cb108ec5f985f4d1cb6ed19` |
| [3GPP TS 32.299 V19.0.0](https://www.3gpp.org/ftp/Specs/archive/32_series/32.299/32299-j00.zip) | `afabe3636ed612045a13916bc30bc7ceaa63364c2d8098b98d60d5893b09ce02` |

Each fixture also records DOCX hashes and definition clauses. The charging
source supplies User-CSG-Information and its enumerations; TS 29.272 supplies
the location grammars. Its application-specific M-bit restrictions apply
only to S6a. Identical inherited
definitions are reused, including MSC-Number, SGSN-Name and SGSN-Realm.

Specification discrepancies are resolved as follows:

- SMSMI-Correlation-ID is code 3324, Grouped. Approved
  [CR 0014, C4-141882](https://www.3gpp.org/ftp/tsg_ct/WG4_protocollars_ex-CN4/TSGCT4_66bis_Sophia_Antipolis/Docs/C4-141882.zip)
  (CP-140783, incorporated in V12.5.0) corrected Table 6.3.3.1/1 allocations,
  leaving the §6.3.3.13 header's 3308 stale. Annex B incorrectly lists CR 0014
  under CP-140767; the [3GPP CR database](https://portal.3gpp.org/ChangeRequests.aspx?q=1&specnumber=29.338)
  records C4-141882 as approved through CP-140783 at CT#66, which is the
  approval reference used here. The CR archive SHA-256 is
  `8d3789f397de0b92fc89f396ed6b748e91f397549676fe5702037907f53e3e58`.
  TS 29.230 V19.3.0 also assigns 3324 but incorrectly calls it Unsigned32;
  TS 29.338's table and grouped grammar determine its type.
- SM-Delivery-Timer uses the precise Unsigned32 type in Table 6.3.3.1/1.
  The generic “Integer” wording in §6.3.3.10 dates to V11.0.0. Approved
  [CR 0018r1, C4-152177](https://www.3gpp.org/ftp/tsg_ct/WG4_protocollars_ex-CN4/TSGCT4_71_Anaheim/Docs/C4-152177.zip)
  (CP-150776, incorporated in V13.0.0) retained Unsigned32 in the table;
  no identified CR explicitly corrects the prose. Its archive SHA-256 is
  `50150da1bb3773dddbe8fb4fd1f7676c3019ef4427845eed09c56df2d75cca18`.
- S6c Table 5.3.3.1/2's SMSMI-Correlation-ID and Destination-SIP-URI
  references should point to §§6.3.3.13 and 6.3.3.16, not §6.3.3.2.
- SGd §6.3.2.3 uses SM-Delivery-Outcome, although Table 6.3.3.1/2 omits it;
  the fixture includes its S6c definition.
- S6c alone uses the Serving-Node and Additional-Serving-Node SMS grammars
  in §§5.3.3.6–7. SGd, S6a and SWx use their defining TS 29.173 V19.0.0
  §§6.4.3, 6.4.8 grammars. All printed extension points are preserved. The six
  per-node delivery-outcome grammars omit an extension point in the source.
- MME-Realm and MME-Number-for-MT-SMS require M in S6c. SGd retains the
  source M-clear MME-Realm and MME number, and explicitly clears SGSN-Number and
  External-Identifier. External-Identifier retains source M,V in S6c.

`sms_spec_test.go` compares the effective `dict.Default` view, all ordered
rules, fixed positions, cardinalities, exact AVP and member flag sets,
exact enumeration labels and values, PXY, recursive closure and vendor declarations.
`sms_wire_spec_test.go` exercises all 221 application/definition combinations,
including optional nested members, and all ten command bodies.
`sms_vendor_spec_test.go` exercises CER vendor advertisement for every bundle.

The source fixtures preserve explicit `shared_dictionary_gap` records for
shared files excluded from this refresh. Tests pin these known deviations
separately instead of treating them as normative expectations:

- `base.xml` retains obsolete MAY-P metadata on 15 reused AVPs listed in
  the fixtures; RFC 6733 §4.5 has no such MAY-P column.
- `base.xml` lacks Proxy-Info's `*[AVP]` (RFC 6733 §6.7.2) and Failed-AVP's
  `1*{AVP}` (RFC 6733 §7.5). Failed-AVP payloads are intentionally exempt
  from normal grouped validation because they carry error evidence.
- `tgpp_ro_rf.xml` retains MAY-P for User-CSG-Information, absent from
  TS 32.299 V19.0.0 Table 7.2.0.1. Its source M,V flags and grouped grammar
  are inherited by S6c/SGd; the shared metadata gap remains explicit.

User-CSG-Information and eNodeB-ID retain their defining M,V flags in
S6c/SGd (TS 32.299 V19.0.0 Table 7.2.0.1; TS 29.217 V19.0.0 Table 5.3.1.1).
The latter permits P. Neither TS 29.338 reuse table overrides these flags.
S6a's Table 7.3.1/2 M-clear rules apply only within S6a. Extended-eNodeB-ID's
defining TS 29.217 table itself forbids M, so it needs no such distinction.

`sms_inheritance_spec.json` pins all twelve affected definitions in the
S6a and SWx effective views. Its `swx_local_definitions` additionally pins
the complete definitions of the four SWx overrides: types, encryption metadata,
exact flag sets, enumeration labels and values, and ordered member rules.
S6a locally clears M for MME-Number-for-MT-SMS
(TS 29.272 V19.6.0 Table 7.3.1/1, §7.3.159) and External-Identifier
(Table 7.3.1/2, §§7.3.2, 7.3.195). MME-Realm is absent from those S6a
tables; its local override preserves the defining TS 29.173 V19.0.0
Table 6.4.1/1, §6.4.12 policy for an optional inherited extension. These
are application-wide definitions, not member-specific flag exceptions.

The other nine definitions are absent from TS 29.272 §7.3.1's application
and reuse tables. All twelve are absent from TS 29.273 V19.2.0 §8.2.3.0
Tables 8.2.3.0/1–2 and the SWx grammars. Both specifications explicitly
exclude unlisted non-base AVPs from required support. When these definitions
are exposed by inheritance, the defining specification governs: an absent
row does not authorize importing another application's flag or grammar override.
S6a and SGd locally restore the two TS 29.173 node grammars; SWx inherits the
S6a copies. Keeping the parent map requires four Grouped copies, whereas
reparenting S6a directly to Ro/Rf would require 16 definitions to preserve its
command and grouped-member closure; eNodeB-ID is already defined locally in
S6a. SWx locally restores the source M,V flags
for External-Identifier, GMLC-Address, User-CSG-Information and eNodeB-ID;
TS 29.273 Table 8.2.3.0/2 specifies no overrides for them. These AVPs remain
optional extensions rather than added SWx procedure requirements. This
correction isolates S6a policy only for these four AVPs, not the entire inherited
SWx view. Other inherited TS 29.336 V20.0.0 AVPs, including SCEF-Reference-ID and
Monitoring-Event-Configuration, still expose S6a M-clear overrides in SWx.
They do not occur in SWx message grammars; their inherited definitions remain
a known limitation outside this refresh.

The SWx prose “External Identifier” in §§8.2.3.1–2 refers to Subscription-ID,
not the External-Identifier AVP. The audited
[TS 29.273 V19.2.0 archive](https://www.3gpp.org/ftp/Specs/archive/29_series/29.273/29273-j20.zip)
has SHA-256 `9ca4a7c8de3ce7fa82ac5ed6c39088ca69799137944df0d90ba6caf4697b1531`.

TS 29.338 still cites obsolete RFC 2234 (§§5.3.2.1, 6.3.2.1) and RFC 4960
(§4.6). Current grammar interpretation uses RFC 5234, updated by RFC 7405;
current SCTP is RFC 9260. RFC 6733 remains current, updated by RFC 7075 and
RFC 8553. RFC Editor and filtered Datatracker relationship queries agreed;
verified errata were checked, including RFC 6733 Errata 4803 and 4808.
Held and rejected proposals were not applied. The Diameter working group is
concluded; the active SCTP DTLS extension draft is not a replacement for
RFC 9260.

`swx_spec.json` covers TS 29.273 V19.2.0 (2026-03): all 16 AVPs in
Table 8.2.3.0/1, three Enumerated registries with six values, five Grouped
grammars, all 43 reused entries in Table 8.2.3.0/2, and eight command bodies
in §§8.2.2.1–8.2.2.4. The command bodies contain 20, 17, 13, 12, 20, 16,
12 and 10 ordered rules. The [3GPP portal](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=1691)
confirmed V19.2.0 as latest on 2026-10-07. The
[official archive](https://www.3gpp.org/ftp/Specs/archive/29_series/29.273/29273-j20.zip)
SHA-256 is `9ca4a7c8de3ce7fa82ac5ed6c39088ca69799137944df0d90ba6caf4697b1531`;
the enclosed document SHA-256 is
`bed4ee977fe0846c74d6cf3e7c649923d4296bde046c7da6555291ee70ec2b4c`.

`swx_copied_spec.json` pins 20 Grouped roots and the entire named-member
closure, together with every reused scalar and command member: 169 distinct
AVPs, 31 Grouped grammars with 197 member rules, and 37 Enumerated registries
with 264 values. The union of both fixtures also contains 169 distinct AVPs.
The primary tables, CCF, enumerations and SWx-specific overrides were
extracted from Word XML. Reused metadata comes from the defining source
tables, existing independent Gx/Rx/S6a source extractions, and current RFC
text and flag tables. Neither fixture is extracted from dictionary XML.
Extraction tooling remains outside the repository.

Additional source archives and their SHA-256 digests:

| Source | Archive SHA-256 |
| --- | --- |
| [TS 29.229 V19.1.0](https://www.3gpp.org/ftp/Specs/archive/29_series/29.229/29229-j10.zip) | `376b8793234f2f952a9f52a37771c56e51677e160160e5d48b1bf29585ac3b1e` |
| [TS 29.272 V19.6.0](https://www.3gpp.org/ftp/Specs/archive/29_series/29.272/29272-j60.zip) | `c40fd1834046f87655f4c7c1acd137b0f8f658a91f6cc83a215592ca8326a4b1` |
| [TS 29.061 V20.1.0](https://www.3gpp.org/ftp/Specs/archive/29_series/29.061/29061-k10.zip) | `848ae9641136231195f7e8c1d045c8ad8ac7bab22541ba860b7851fdaa936f8f` |
| [TS 29.336 V20.0.0](https://www.3gpp.org/ftp/Specs/archive/29_series/29.336/29336-k00.zip) | `038bbadbcdc3a6715a06371f30aa31846cba37d4687f1379df1b0bdd29d044ac` |
| [TS 32.299 V19.0.0](https://www.3gpp.org/ftp/Specs/archive/32_series/32.299/32299-j00.zip) | `afabe3636ed612045a13916bc30bc7ceaa63364c2d8098b98d60d5893b09ce02` |
| [TS 32.422 V20.3.0](https://www.3gpp.org/ftp/Specs/archive/32_series/32.422/32422-k30.zip) | `ce7492846ba9efdcf4e9f0ca4153856b34854a62c7f9d7414e27161129ecf1c1` |
| [TS 29.212 V20.0.0](https://www.3gpp.org/ftp/Specs/archive/29_series/29.212/29212-k00.zip) | `2a18b6817f72e7f52961e939142497e1cd5ec0c90f52a2057c57374ea5a00958` |
| [TS 29.214 V20.0.0](https://www.3gpp.org/ftp/Specs/archive/29_series/29.214/29214-k00.zip) | `639cbcba519539918c8965fdf6399307094b16d87306878d0ed588ac6335659c` |

Logical-Access-ID uses ETSI ES 283 034 V2.2.0 Table 10, §7.3.3, whose PDF digest is
recorded with Sy above. The SWx vendor declaration includes ETSI 13019 for
this member of Access-Network-Info; 3GPP 10415 remains the application author.

SWx interpretation and normalization:

- Flag sets are compared exactly and use comma-separated `M,V` syntax.
  Whitespace, `Subscription-ID` capitalization and established `TGPP-`
  spellings are normalized. The duplicate closing bracket after OC-OLR in
  MAA/SAA is typography, not an additional grammar element.
- Access-Network-Info uses code 1526. Both its current table and §5.2.3.24
  agree after [CR 0557, C4-260085 / CP-260030](https://portal.3gpp.org/ChangeRequests.aspx?q=1&release=194&versionId=97641),
  approved for V19.2.0. The CR portal record was checked; the change document
  itself could not be downloaded.
- Emergency-Services is defined in §7.2.3.4. Table 9.2.3.2.1/1's reference
  to §7.2.3.5 points to AAR-Flags instead; the defining clause and STa table
  agree. ERP-Authorization remains Unsigned32 despite its two named values.
- Subscription-Id retains the explicitly optional members in §8.2.3.2;
  SIP-Auth-Data-Item retains the SWx grammar in §8.2.3.9. APN-Configuration
  inherits the full current TS 29.272 grammar: §8.2.3.7 says some members
  need not be included, without prohibiting them or removing extensions.
- SCEF-ID inside APN-Configuration follows TS 29.336 V20.0.0
  Table 8.4.1-1 and §8.4.5: DiameterIdentity, M,V required, encryption
  forbidden. SWx Table 8.2.3.0/2 supplies no override, so S6a's
  application-specific M-bit prohibition does not apply. A local SWx
  definition restores the defining specification; SAA tests require M,V
  and reject V-only SCEF-ID before and after a wire round trip.
- Supported-Features inherits its source grammar. TS 29.229 V19.1.0 §7.2.1
  forbids its M bit in answers; four command-member rules apply this
  restriction without changing the AVP's request policy.
- Load inherits RFC 8583's extension point and member flags. SWx clears M
  on Load itself, without the recursive M prohibition specified for Gx/Rx.
  SourceID therefore retains its RFC 8581 §7.4 policy. §8.2.3.26's reference
  to Annex E is editorially stale; SWx load control is in Annex F.
- The reused Area-Scope header in TS 29.272 §7.3.138 prints 1623,
  which belongs to Job-Type. Table 7.3.1/1 and current TS 29.230 V19.3.0
  Table 7.1/1 assign Area-Scope 1624. The introducing CR records are
  TS 29.272 CR 0329r2 (C4-110777) and TS 29.230 CR 0207r2 (C4-110780),
  approved together in CP-110087 for V10.2.0. Their portal records were
  checked, but the edit marks were unavailable. The independently fetched
  [TS 29.230 V19.3.0 archive](https://www.3gpp.org/ftp/Specs/archive/29_series/29.230/29230-j30.zip)
  SHA-256 is `735ec5b55d998504a9dc9e47cb75fa519d2db640cba2f0abc2e92b46d181a173`;
  the enclosed document SHA-256 is
  `d0a0da283745aa3390b66f3f1e9129a59339cc9be57237f2d3c7f27a588f98e7`.
- RFC 4004 §7.11 and Verified Erratum 3234 define MIP-Home-Agent-Host as
  Grouped. RFC 5447 and RFC 5778 Verified Errata 3034/3035 correct the
  MIP6-Agent-Info name. Their grammars retain their extension points.
- Base RFC 6733 §4.5 and RFC 8506 §8 flag tables no longer have the older
  P-bit permission column. Fifteen base AVPs and Ro/Rf's BSSID retain
  informational `may="P"` in their shared definitions. The fixtures record
  these as `known_shared_metadata_gap` entries while retaining the canonical
  source metadata. Tests accept only the source MAY set or the documented
  legacy `P` set, and require inheritance instead of SWx-local copies.
  These shared metadata gaps have no validation behavior effect and remain
  for their respective shared-dictionary audits.
- TS 29.273 V19.2.0 §8.2.2.2 omits PXY in the published PPR header,
  while its PPA includes PXY; §8.2.2.3 likewise uses PXY in SAR/SAA.
  The dictionary and fixture require PXY on both PPR and PPA under
  RFC 6733 §6.2's rule that the answer P bit match the request. The fixture
  retains the original PPR header in `published_header` and explains this
  deliberate correction in `proxiability_note`. The omission has persisted
  in every published version since V8.0.0. Cx PPR, also command code 305,
  uses REQ, PXY (TS 29.229 V19.1.0 §6.1.11). RFC 6733 §3 requires local
  processing when P is clear. With `ValidateRequests` enabled, a P-clear
  SWx PPR following the published header is answered with
  DIAMETER_INVALID_HDR_BITS (3008). No correcting CR was found in the
  accessible history.

Tests compare the effective `dict.Default` application, exact flag sets,
identities, types, enums, ordered rules, fixed positions and cardinalities.
Wire tests round-trip all 169 AVPs and eight command bodies, exercise
Grouped and command boundaries, and verify answer-scoped feature flags.
The vendor tests pin both SWx-only and full-default CER advertisements.

RFC Editor and Datatracker relationships and errata were cross-checked on
2026-10-07. The current sources include RFC 6733 with 7075/8553, RFC 7683
with 8581, RFC 5580 with 8559, RFCs 4004, 5447, 5778, 7944, 8506 and 8583,
and RFC 5234 with 7405. DIME is concluded; no pending replacement for the
SWx dictionary encodings was identified. RADEXT and EMU work concerns
RADIUS transport or encapsulated EAP behavior, not these Diameter grammars.

TS 29.273 still cites obsolete RFCs 4006 (now 8506), 4005 (7155), 4282
(7542), and in an STa body reference 3588 (6733). RFC 5448 is current but
updated by 9048 and 9678; it is not obsolete. Held/rejected proposals were
not applied: RFC 6733 Held 4210/4234/5084 and Rejected
4209/4462/4463/4473/4931/6833; RFC 5447 Held 1695/1934; RFC 5580 Held 5465;
RFC 5234 Held 2820/2914/6172/6173 and Rejected
1423/3096/4040/4564/5110/4361; RFC 7405 Rejected 5334.
Reported RFC 6733 6832 and RFC 7683 5277/5278 remain unverified.

Value-dependent procedures remain outside static dictionary validation:
feature negotiation, conditional user-profile contents, allowed identity
kinds, reserved bit-mask values, authentication vectors, and the
Auth-Session-State value required by §8.2.4. The PPR header correction
above is explicit; these fixtures do not implement encapsulated EAP,
RADIUS, DNS, or mobility protocols.

`nasreq_spec.json` and `credit_control_spec.json` cover the current IETF
NASREQ and Credit-Control applications. Their tables and ordered grammars
were extracted from the RFC Editor's plain-text publications, independently
of dictionary XML; enumerations use the current IANA RADIUS and AAA XML
registries. RFC typography and the explicitly identified Verified errata
are normalized before comparison. There are no 3GPP table/clause conflicts
in these RFC-owned definitions requiring a CR override.

| Fixture | Source coverage |
| --- | --- |
| `nasreq_spec.json` | RFC 7155: 78 AVPs including Erratum 6119, four supplemental RADIUS identities, 14 enumerations with 132 assigned values, two Grouped grammars, ten command bodies with 358 ordered rules |
| `nasreq_reused_spec.json` | RFC 6733: 37 reused AVPs, including recursive Proxy-Info members and seven current IANA registries |
| `credit_control_spec.json` | RFC 8506: all 68 §8 AVPs, 46 assigned enum values, 17 Grouped grammars, CCR/CCA with 30/29 RFC rules |
| `credit_control_reused_spec.json` | Source grammars and bounded shared gaps for RFC 6733 Proxy-Info/Failed-AVP and RFC 5777 Filter-Rule |

The archived source bytes have these SHA-256 digests:

| Source | SHA-256 |
| --- | --- |
| [RFC 7155 text](https://www.rfc-editor.org/rfc/rfc7155.txt) | `f100a5a47def22bda012369e8926f5d17c57b9a73a0fe4daeac16bb01b272cd5` |
| [RFC 8506 text](https://www.rfc-editor.org/rfc/rfc8506.txt) | `8a486839f1995b87c79dafdc4ebf0d04ab88392adeb00987f5170b2bc621204c` |
| [RFC 6733 text](https://www.rfc-editor.org/rfc/rfc6733.txt) | `b0117adedd43f9f44e444f64cd7360709c351aa27ea288d9c664c2800da8fa26` |
| [RFC 5777 text](https://www.rfc-editor.org/rfc/rfc5777.txt) | `fac6d1f959730137007f1eec4826d6e2bd1f937ecfd26ee31e70796174ee8fc8` |
| [IANA RADIUS registry](https://www.iana.org/assignments/radius-types/radius-types.xml) | `870352bc393645882a5e0c7210d13e055c04741af47372cf068819628e75e238` |
| [IANA AAA registry](https://www.iana.org/assignments/aaa-parameters/aaa-parameters.xml) | `67e1f78147ac95886436dc9459611f1821159fd3d411d98f2781db2b4820b720` |

NASREQ applies RFC 7155 Verified Errata 5993–5995 to the command names and
6119 to Origin-AAA-Protocol. Reported Erratum 6029 is not applied:
QoS-Filter-Rule retains the published M policy; V is prohibited independently
by RFC 6733 §4.1 for vendor-zero IETF AVPs, despite the blank application-table
cell. The fixture records both the printed cell and the governing base rule. All ten command bodies
retain `*[AVP]`, Session-Id is fixed first, and NAS-IP-Address is optional.
CHAP-Response is optional in the §4.3.4 grammar, and CHAP-Auth retains its
extension point. RFC 7155 §4.3.5 nevertheless requires CHAP-Response when
CHAP-Algorithm is 5 (MD5). Senders must enforce that condition; a static
optional rule cannot express it. The no-response boundary test asserts
grammar acceptance only, not MD5 sender compliance.
Tunneling has no extension point in §4.5.1. Login-Service excludes the
unassigned value 7. The current tables have no P/encryption columns, so
legacy annotations are removed from the 82 NASREQ-local and 68 RFC 8506
AVPs. Flag sets are compared exactly, using comma-separated syntax.

RFC 7155 names NAS-IP-Address, NAS-IPv6-Address, NAS-Identifier and State
in command grammars but omits their Diameter datatype/M-bit rows. Their
existing encodings are preserved, with RADIUS identities and data categories
checked against IANA. M is optional because RFC 7155 assigns no Diameter
flag rule to these attributes; no obsolete M-bit requirement is retained.
Tests require both M-set and M-clear to pass ValidateOutgoing, before and
after serialization. The encodings are not presented as complete normative
Diameter definitions. RFC 6733 §4.1
prohibits V on these RADIUS-compatible codes. No other AVP copies are added.

Credit-Control restores EVENT_REQUEST, optional Currency-Code in CC-Money,
optional Cost-Unit in Cost-Information, optional Exponent in Unit-Value,
and seven missing Grouped extension points. Subscription-Id-Extension and
Redirect-Server-Extension permit one extension, as printed in §§8.58/8.64;
User-Equipment-Info-Extension retains §8.52's existing singleton bound.
The exact-one-member sender requirements remain outside static grammar
validation. CCR preserves the pre-existing Service-Information addition
from Ro/Rf separately from its RFC rules. All other non-RFC 8506 additions
remain outside this refresh.

Tests compare the effective application 1/4 views, source metadata,
enumerations, recursive reused members, fixed positions, cardinalities,
member prohibitions and PXY. Wire tests round-trip the 150 local AVPs and
the available reused-source closure, all twelve command bodies, optional
member boundaries, closed groups and bounded/unbounded extension points.
Command and CHAP-Auth extension tests use a known non-member AVP,
Host-IP-Address, so removing the wildcard makes validation fail. Reused
enum comparisons normalize typography on both sides, including all thirty
IANA Termination-Cause values when the base definition is refreshed.
The CER test pins every bundled selection and the complete dictionary's
Supported-Vendor-Id advertisement. Cross-application enumeration consistency
is checked by the shared registry test.

The source tests explicitly bound these outstanding shared definitions:

- Base Proxy-Info lacks RFC 6733 §6.7.2's `*[AVP]`; Failed-AVP lacks
  §7.5's `1*{AVP}`. Their source grammars remain in the fixtures.
- Base Termination-Cause contains the eight RFC 6733 §8.15 values rather
  than all thirty current IANA values; assigned values 11–32 are missing.
- Reused base AVPs retain legacy P/encryption metadata. Tests permit only
  identified existing metadata or the canonical current source values.
- Filter-Rule (509), an existing non-RFC 8506 definition in the charging
  dictionary, is an empty Grouped stub. RFC 5777 §3.2 requires eight named
  member rules and an extension point. Its complete descendant definitions
  need a separate RFC 5777 refresh; these tests do not claim that closure
  is implemented.

RFC Editor JSON and filtered Datatracker relationship records were checked
on 2026-10-07 and agree: RFCs 7155 and 8506 are current, replacing 4005 and
4006. RFC 6733 is updated by 7075/8553, RFC 7683 by 8581, RFC 2865 by
2868/3575/5080/6929/8044/9765, RFC 2868 by 3575, RFC 3575 by 6929 and
RFC 3162 by 8044. RFCs 2867, 5777, 7944, 8581 and 8583 have no replacements or
updates. The update documents were checked as well. DIME is concluded;
RADEXT's active Connect-Info work describes Wi-Fi attribute content and
is not a normative replacement for these Diameter encodings.

RFC 6733 Verified Erratum 4803 supplies the corrected CCF header literal.
Its other Verified errata, RFC 7683 Erratum 4549, RFC 5777 Errata 2333–2336,
and the RADIUS source corrections were reviewed without additional changes
to the scoped Diameter definitions. Non-Verified proposals remain unapplied:
RFC 7155 Reported 6029; RFC 6733 Reported 6832, Held 4210/4234/5084,
Rejected 4209/4462/4463/4473/4931/6833; RFC 7683 Reported 5277/5278;
RFC 5777 Held 2337; RFC 2865 Held 6915/8739/9034 and Rejected 4077;
RFC 3162 Held 3217 and Rejected 1923; RFC 3575 Rejected 5093;
RFC 5080 Held 4623 and Rejected 4476; RFC 8044 Reported 8671.
RFC 8506 has no errata. Extraction tooling remains outside the repository.
