print_usage() {
    echo 'Usage: ./ip-td.sh ${HOSTNAME}'
}

if [[ $# -eq 0 ]] ; then
    echo 'Error: hostname is not specified!'
    print_usage
    exit 1
fi

HOSTNAME="$1"

ssh ${HOSTNAME} -o "ProxyCommand=nc -X connect -x localhost:10500 %h %p"
