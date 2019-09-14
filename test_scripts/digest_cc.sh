TMP_SEDFILE="build/embedded_config.sed"

# Digest the clienConf to hex
EMBEDDED_CC=$(hexdump -ve '"\\\\\\\\\x" 1/1 "%.2x"' $1);

# Create search and replace rule
printf "s/embeddedClientConf = \"[x0-9a-fA-F\\]+\"/embeddedClientConf = \"$EMBEDDED_CC\"/g" > $TMP_SEDFILE

# Replace the old ClientConf from the psiphon config
sed -r -i '' -f $TMP_SEDFILE $2

rm $TMP_SEDFILE
