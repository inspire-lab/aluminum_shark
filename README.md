# Aluminum Shark
Privacy-Preserving Neural Networks with TensorFlow and Homomorphic Encryption

Currently, it only works on Linux. Tested on Ubunut 20.04

## Creating a conda environment with Aluminum Shark binaries installed

The easiest way is to use our prebuilt binaries. 

1. Clone the Repository 
2. Run `tools/install_conda_environment.sh <dir>`. Replace `<dir>` with the path
   to where the conda environment should be installed.
3. Activate the environment by running `conda activate <dir>` (Note: `<dir>` 
   needs to be the absolute path to the installed environment)

Requirements:
 - Linux 
 - Python 3
 - requests (pip3 install requests)
 - conda (anaconda3 or miniconda3)


## Build it yourself

To build the code yourself, you the following:
 - bazel to build TensorFlow (https://bazel.build)
 - CMake to build OpenFHE and SEAL (https://cmake.org)
 - Python 3 with numpy (needs to be usable as `python`, not `python3`)
 - git

Unless specified otherwise, all paths are relative to the project root.

### Fetching dependencies 

First, we need to download and build the dependencies. To download the dependencies 
run:

```
./fetch_dependencies.sh
```

### Building dependencies 

#### Building Custom TensorFlow

We need a custom TensorFlow that can run on encrypted data. It is automatically
downloaded with the script from the last step.
Go to `dependencies/tensorflow` and run 
```
./build_and_install.sh
```
This can take quite a long time to build. You can specify the number of build 
jobs, e.g., to use 10 run:
```
./build_and_install.sh 10
```

#### Building SEAL and the SEAL backend

Go to `dependencies/SEAL` and build SEAL by running:

```
mkdir bin 
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=./bin -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF
cmake --build build
cmake --install build
```


Next, we need to build the SEAL backend. From `seal_backend` run
```
make && make install
```

#### Building OpenFHE and the OPENFHE backend

Go to `dependencies/openfhe_development` and build OpenFHE by running:

```
mkdir build
mkdir bin
cd build
cmake -DCMAKE_INSTALL_PREFIX=../bin -DBUILD_STATIC=ON  -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF -DWITH_NATIVEOPT=ON -DWITH_OPENMP=OFF ..
make
make install
```

Next, we need to build the OpenFHE backend. From `openfhe_backend` run
```
make && make install
```

#### Installing Aluminum Shark

Finally, from the project root run:

```
python -m pip install -e .
```

# Run the Example Code

There is a simple example in `examples`. It runs a simple neural network over 
encrypted data. 
