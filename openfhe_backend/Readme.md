# Building OpenFHE

From `depencies` run

```
git clone https://github.com/openfheorg/openfhe-development.git
cd openfhe-development/
mkdir build
mkdir bin
cd build
cmake -DCMAKE_INSTALL_PREFIX=../bin -DBUILD_STATIC=ON ..
make
make install

```