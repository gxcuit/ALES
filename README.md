# Achieving low-entropy secure cloud data auditing with file and authenticator deduplication
## 1. The scheme details
  Please kindly refer to the paper.(under review)
## 2. Config
### 2.1 ubuntu
1. prepare
```shell
sudo apt-get update
sudo apt-get install m4
sudo apt-get install flex
sudo apt-get install bison
apt-get install lzip
apt-get install gcc automake autoconf libtool make
```
2. install GMP
```shell
wget --no-check-certificate http://gmplib.org/download/gmp/gmp-6.1.2.tar.lz
lzip -d gmp-6.1.2.tar.lz
tar xvf gmp-6.1.2.tar
cd gmp-6.1.2
./configure
sudo make
sudo make check
sudo make install
```
3. install pbc
```shell
wget --no-check-certificate https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar xvf pbc-0.5.14.tar.gz
cd tar xvf pbc-0.5.14.tar.gz
./configure
sudo make
sudo make install
```
4. run 
```shell
./config
```
