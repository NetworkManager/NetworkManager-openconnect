#!/bin/bash

if [ "$OPENCONNECT_DIR" = "" ]; then
    OPENCONNECT_DIR=../openconnect
fi
if [ "$OPENCONNECT_BUILD_DIR"  = "" ]; then
    OPENCONNECT_BUILD_DIR="$OPENCONNECT_DIR"
fi

# The openconnect.pot file is made available by a cron job on this server, along
# with the project's web site which is also held in the git repository. There's
# race condition here, if the server is updating as we run this script. But it's
# unlikely that the string in question would move far, so it should be good enough.
COMMIT="$(git -C "$OPENCONNECT_DIR" rev-parse HEAD)"
TOPLEVEL="$(git -C "$OPENCONNECT_DIR" rev-parse --show-toplevel)"
if ! echo $COMMIT | grep -E -q "[a-f0-9]{40}"; then
    echo "Error: Failed to fetch commit ID from $OPENCONNECT_DIR"
    exit 1
fi

pushd $OPENCONNECT_BUILD_DIR
make po/openconnect.pot || exit 1
popd

COMMIT=$(echo $COMMIT | cut -c1-10)
GITWEB=https://git.infradead.org/users/dwmw2/openconnect.git/blob/
OUTFILE=openconnect-strings-$COMMIT.txt
NR_STRINGS=$(grep -c ^msgid $OPENCONNECT_BUILD_DIR/po/openconnect.pot)
NR_DONE=0

cat >$OUTFILE <<EOF
This file contains strings from the OpenConnect VPN client, found at
https://www.infradead.org/openconnect/ and browsable in gitweb at
https://git.infradead.org/users/dwmw2/openconnect.git

We do this because NetworkManager-openconnect authentication dialog
uses a lot of strings from libopenconnect, which also need to be
translated too if the user is to have a fully localised experience.

For translators looking to see source comments in their original context
in order to translate them properly, the URLs by each one will give a
link to the original source code.
EOF

cat $OPENCONNECT_BUILD_DIR/po/openconnect.pot |
while read -r line; do
    case "$line" in
	"#:"*)
	    echo >>$OUTFILE
	    for src in ${line###: }; do
		THISCOMMIT=${COMMIT}
		FILE=${src%%:*}
		LINE=${src##*:}
		eval `git -C "$TOPLEVEL" blame $COMMIT -fnswL $LINE,$LINE -- $FILE |
		    sed "s/\([0-9a-f]\+\) \([^ ]\+\) \([0-9]\+\) .*/THISCOMMIT=\1\nFILE=\2\nLINE=\3\n/"`
		echo "// ${GITWEB}${THISCOMMIT}:/${FILE}#l${LINE}" >>$OUTFILE
	    done
	    real_strings=yes
	    ;;
	"msgid "*)
	    if [ "$real_strings" = "yes" ]; then
		echo -n "_(${line##msgid }" >>$OUTFILE
		in_msgid=yes
	    fi
	    NR_DONE=$((${NR_DONE} + 1))
	    echo -en "\rDone $NR_DONE/$NR_STRINGS"
	    ;;
	"msgstr "*|"")
	    if [ "$in_msgid" = "yes" ]; then
		in_msgid=no
		echo ");" >>$OUTFILE
	    fi
	    ;;
	*)
	    if [ "$in_msgid" = "yes" ]; then
		echo >>$OUTFILE
		echo -n "$line" >>$OUTFILE
	    fi
	    ;;
   esac
done
echo ""
MESSAGES=$(grep -c "^_(" openconnect-strings-$COMMIT.txt)

echo "Got $MESSAGES messages from openconnect upstream"

if [ "$MESSAGES" -lt 100 ]; then
    echo "Fewer than 100 messages? Something went wrong"
    rm openconnect-strings-$COMMIT.txt
    exit 1
fi

# Filter out the noise in openconnect-strings.txt for comparison:
#
# /^\($\|\/\/\)/	# Match lines matching ^$ (empty) or ^//
#     d;		# ... and delete them.
# :a			# Label 'a'
# /"$/			# Match lines ending with a "
#     {N;ba};		# Append the next line, branch back to 'a'
# s/\n//g		# Remove any newline *within* a buffer
#
NEWSHA=$(sed '/^\($\|\/\/\)/d;:a;/"$/{N;ba};s/\n//g' openconnect-strings-$COMMIT.txt | sort | sha1sum)
OLDSHA=$(sed '/^\($\|\/\/\)/d;:a;/"$/{N;ba};s/\n//g' openconnect-strings.txt | sort | sha1sum)
if [ "$NEWSHA" != "$OLDSHA" ]; then
    echo New strings
    mv openconnect-strings-$COMMIT.txt openconnect-strings.txt
else
    echo No new strings. Not changing openconnect-strings.txt
    rm openconnect-strings-$COMMIT.txt
fi

make -C po NetworkManager-openconnect.pot || exit 1
for a in po/*.po ; do
    echo Comparing $a...
    if [ -r $OPENCONNECT_DIR/$a ]; then
	msgattrib -F --no-fuzzy $OPENCONNECT_DIR/$a > $a.openconnect 2>/dev/null
	msgmerge -q -N -F $a -C $a.openconnect po/NetworkManager-openconnect.pot > $a.merged
	msgmerge -q -N -F $a po/NetworkManager-openconnect.pot > $a.unmerged
	if ! cmp $a.merged $a.unmerged; then
	    echo New changes for $a
	    mv $a.merged $a
	fi
	rm -f $a.openconnect $a.merged $a.unmerged
	msgattrib -F --no-fuzzy $a > $a.nmo
	msgmerge -q -N -C $OPENCONNECT_DIR/$a -F $a.nmo $OPENCONNECT_BUILD_DIR/po/openconnect.pot > $OPENCONNECT_DIR/$a.merged1
	msgattrib -F --no-fuzzy --no-obsolete $OPENCONNECT_DIR/$a.merged1 > $OPENCONNECT_DIR/$a.merged2
	msgmerge -q -N -F $OPENCONNECT_DIR/$a $OPENCONNECT_BUILD_DIR/po/openconnect.pot > $OPENCONNECT_DIR/$a.unmerged1
	msgattrib -F --no-fuzzy --no-obsolete $OPENCONNECT_DIR/$a.unmerged1 > $OPENCONNECT_DIR/$a.unmerged2
	if ! cmp $OPENCONNECT_DIR/$a.merged2 $OPENCONNECT_DIR/$a.unmerged2; then
	    echo New changes for OpenConnect $a
	    mv $OPENCONNECT_DIR/$a.merged2 $OPENCONNECT_DIR/$a
	fi
	rm -f $OPENCONNECT_DIR/$a.merged2 $OPENCONNECT_DIR/$a.merged1 $OPENCONNECT_DIR/$a.unmerged2 $OPENCONNECT_DIR/$a.unmerged1 $a.nmo
    fi
done

