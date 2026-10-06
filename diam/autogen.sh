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

cat $dict | "$SED" \
	-e 's/-//g' \
	-ne 's/.*command code="\(.*\)" .* name="\(.*\)".*/\2 = \1/p' \
	| "$SED" -e 's/^[[:lower:]]/\u&/' | sort -u >> $src

printf ')\n// Short Command Names\nconst (\n' >> $src

cat $dict | "$SED" \
	-e 's/-//g' \
	-ne 's/.*command code="[0-9]*".*\s.*short="\([^"]*\).*/\1R = "\1R"\n\1A = "\1A"/p' \
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

cat $dict | "$SED" \
    -e :1 -e 's/\("[^"]*\)[[:space:]]\([^"]*"\)/\1_\2/g;t1' \
    -ne 's/\s*<application\s*id="\([0-9]*\)".*name="\(.*\)".*/\U\2_APP_ID = \1/p' \
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
