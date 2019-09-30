#!/bin/sh

# This Script is a psiphon specific tool to 
#   1. digest the clientConf of the current branch into the 
#      format used in psiphons embedded_config.go
#   2. Perform search and replace on the embedded_config.go file to
#      remove the old clientconfig and replace with new digested value.
#
# Use:
#   $ psiphon_digest_cc.sh $PATH_TO_ASSETS/ClientConf $PATH_TO_PSIPHON_CORE/psiphon/common/tapdance/embedded_config.go
#
# Note: This will replace the value inline in the Psiphon embedded config.

if [ "$#" -ne 2 ]; then
    echo "Not enough input arguments:"
    echo '$ psiphon_digest_cc.sh $PATH_TO_ASSETS/ClientConf $PATH_TO_PSIPHON_TD_CORE/embedded_config.go'
    exit 1
fi

TMP_SEDFILE="build/embedded_config.sed"

# Digest the clienConf to hex
EMBEDDED_CC=$(hexdump -ve '"\\\\\\\\\x" 1/1 "%.2x"' $1);

# Create search and replace rule and store to sed scriptfile (can be too long for sed inline)
printf "s/embeddedClientConf = \"[x0-9a-fA-F\\]+\"/embeddedClientConf = \"$EMBEDDED_CC\"/g" > $TMP_SEDFILE

# Replace the old ClientConf from the psiphon config
sed -r -i '' -f $TMP_SEDFILE $2

rm $TMP_SEDFILE
