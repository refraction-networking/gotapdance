print_usage() {
    echo 'Usage: ./nc_send.sh ${SIZE}'
    echo '  ${SIZE} format examples: 67k, 22m '
}

gen_file() {
	mkdir -p random_files
	if [ ! -f $rand_filename ]; then
		head -c $size </dev/urandom > $rand_filename
		if [ $? -ne 0 ]
		then
			echo "Generation of file with size ${size} failed!"
			print_usage
			rm $rand_filename
			exit 2
		fi
	fi
}

if [[ $# -eq 0 ]] ; then
    echo 'Error: send message size is not specified!'
    print_usage
    exit 1
fi


size="$1"
rand_filename="random_files/$size"

website="twitter.com"
port="443"

gen_file
nc -X connect -x 127.0.0.1:10500 $website $port -v < $rand_filename
