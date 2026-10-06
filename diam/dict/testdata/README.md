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
