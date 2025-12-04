make clean
rm -rf install 
mkdir -p install
./Configure --prefix=$(pwd)/install
make CC=gcc CXX=g++  -j9
make install 
