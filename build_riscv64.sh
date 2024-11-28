make clean
./Configure linux64-riscv64
make CC=riscv64-unknown-linux-gnu-gcc CXX=riscv64-unknown-linux-gnu-g++  -j9
