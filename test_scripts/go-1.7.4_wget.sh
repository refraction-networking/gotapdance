export https_proxy=127.0.0.1:10500
export http_proxy=127.0.0.1:10500
#wget https://www.twitter.com
rm go1.7.4.linux-amd64.tar.gz
wget storage.googleapis.com/golang/go1.7.4.linux-amd64.tar.gz
sha256sum go1.7.4.linux-amd64.tar.gz
echo "Expected: 47fda42e46b4c3ec93fa5d4d4cc6a748aa3f9411a2a2b7e08e3a6d80d753ec8b"
