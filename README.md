# spv-node
Bitcoin Simplified Payment Verification Node

## dependencies

### install default packages
```
$ sudo apt-get install build-essential
$ sudo apt-get install libdb5.3-dev libjson-c-dev 
$ sudo apt-get install gnutls-dev libcurl4-gnutls-dev
```

### build bitcoin::libsecp256k1
```
$ mkdir -p tmp && cd tmp
$ git clone https://github.com/bitcoin/bitcoin.git
$ cd bitcoin/src/secp256k1
$ sudo apt-get install autoconf libtool
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
```

### build
```
$ git clone https://github.com/chehw/spv-node.git
$ cd spv-node
$ make clean all
```

### run
```
$ bin/spv-node
```  

