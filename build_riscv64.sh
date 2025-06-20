make clean
rm -rf build 
mkdir -p build
./Configure linux64-riscv64 --prefix=$(pwd)/build
make CC=riscv64-unknown-linux-gnu-gcc CXX=riscv64-unknown-linux-gnu-g++  -j9
make install 
