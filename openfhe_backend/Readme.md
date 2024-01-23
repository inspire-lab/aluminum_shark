# Building OpenFHE

From `depencies` run

```
git clone https://github.com/openfheorg/openfhe-development.git
cd openfhe-development/
mkdir build
mkdir bin
cd build
# use this for a debug build
# cmake -DCMAKE_INSTALL_PREFIX=../bin -DBUILD_STATIC=ON -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF -DCMAKE_BUILD_TYPE=Debug ..
# regular build
cmake -DCMAKE_INSTALL_PREFIX=../bin -DBUILD_STATIC=ON  -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF ..
# possibly a better version using clang and better threading performance. this currently experimental
# cmake -DCMAKE_INSTALL_PREFIX=../bin -DBUILD_STATIC=ON  -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF -DWITH_NATIVEOPT=ON -DWITH_OPENMP=OFF -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ..
make
make install

```