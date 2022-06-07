# Aluminum Shark
Privacy Preserving Neural Networks with TensorFlow und Homomorphic Encryption

Currently only works on Linux. Tested on Ubunut 20.04

# Getting started and build instrcutions

First step: clone this repo

## Fetching dependencies 

To download the dependencies run:

```
./fetch_dependencies.sh
```

## Building dependencies 

### Building Tensorflow

Go to `dependencies/tensorflow` and follow the instructions from the official TensorFlow site: https://tensorflow.org/install/source 
You can skip the GPU instructions and downloading the source.

### Building SEAL

Go to `dependencies/SEAL` and build SEAL by running:

```
mkdir bin 
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=./bin
cmake --build build
cmake --install build
```

### Building the SEAL backend

From `seal_backend` run
```
make && make install
```

# Installing Aluminum Shark

From the project root run:

```
python3 -m pip install -e .
```


