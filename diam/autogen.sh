#!/bin/sh -e
# Copyright 2013-2015 go-diameter authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Generate Diameter constants from our bundled dictionaries
# (dict/bundled/*.xml, which package dict embeds as they are).
#
# Run `sh autogen.sh` to re-generate these files after changing
# dictionary XML files.
os="$(uname -s)"

if [ -z "$SED" ]; then
	if [ "$os" = "Darwin" ]; then
		command -v gsed || {
			echo "gsed is required. install it by running 'brew install gnu-sed'"
			exit 1
		}
		SED="gsed"
	else
		SED="sed"
	fi
fi

# Fix collation for every sort, independently of the host locale.
LC_ALL=C
export LC_ALL

dict=dict/bundled/*.xml

# Read each opening tag as one record, including multiline tags. Extract each
# attribute by name so XML attribute order cannot hide a declaration.
xml_attributes() {
 awk -v element="$1" -v first="$2" -v second="$3" '
 BEGIN { RS = ">" }
 function attribute(key, value) {
  if (match(record, "[[:space:]]" key "[[:space:]]*=[[:space:]]*\"[^\"]*\"")) {
   value = substr(record, RSTART, RLENGTH)
   sub(/^[^"]*"/, "", value)
   sub(/"$/, "", value)
   return value
  }
  return ""
 }
 {
  if (match($0, "<" element "[[:space:]]")) {
   record = substr($0, RSTART)
   print attribute(first) "\t" attribute(second)
  }
 }' $dict
}

## Generate commands.go
src=commands.go

cat << EOF > $src
// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is auto-generated from our dictionaries.

package diam

// Diameter command codes.
const (
EOF

xml_attributes command code name | awk -F '\t' '{ print $2 " = " $1 }' \
 | "$SED" -e 's/-//g' -e 's/^[[:lower:]]/\u&/' | sort -u >> $src

printf ')\n// Short Command Names\nconst (\n' >> $src

xml_attributes command code short | awk -F '\t' '
 { gsub(/-/, "", $2); print $2 "R = \"" $2 "R\"\n" $2 "A = \"" $2 "A\"" }' \
 | "$SED" -e 's/^[[:lower:]]/\u&/' | sort -u >> $src

echo ')' >> $src
cat << EOF >> $src

// Deprecated: Use MultimediaAuth instead.
const MultimediaAuthentication = MultimediaAuth
EOF
go fmt $src

## Generate applications.go
src=applications.go

cat << EOF > $src
// Copyright 2013-2018 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is auto-generated from our dictionaries.

package diam

// Diameter application IDs.
const (
EOF

xml_attributes application id name | awk -F '\t' '
 { gsub(/[[:space:]]/, "_", $2); print toupper($2) "_APP_ID = " $1 }' \
 | sort -u | sort -nk 3 >> $src

printf ')\n' >> $src
go fmt $src

## Generate avp/codes.go
src=avp/codes.go

cat << EOF > $src
// Copyright 2013-2015 go-diameter authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// This file is auto-generated from our dictionaries.

package avp

// Diameter AVP types.
const (
EOF

# TS 29.229 and TS 29.329 use the same AVP name for different codes.
# Keep the established UserData (606), and qualify ShUserData (702).
cat $dict | "$SED" \
	-e 's/avp name="User-Data" code="702"/avp name="Sh-User-Data" code="702"/' \
	-e 's/-Id\([-"s]\)/-ID\1/g' \
	-e 's/-//g' \
	-ne 's/.*avp name="\(.*\)" code="\([0-9]*\)".*/\1 = \2/p' \
	| "$SED" -e 's/^[0-9]/X&/' -e 's/^[[:lower:]]/\u&/' \
	| sort -fu >> $src

printf ')\n' >> $src

go fmt $src
