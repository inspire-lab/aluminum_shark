# Aluminum Shark
Privacy Preserving Neural Networks with TensorFlow und Homomorphic Encryption

Currently only works on Linux. Tested on Ubunut 20.04

# Creating a conda environment with Alumnium Shark binaries installed

1. Clone the Repository 
2. Replace the first line in `tools/token.txt` with your GitHub access token. BE
   CAREFULL TO NEVER COMMIT YOUR TOKEN!!
3. Run `tools/install_conda_environment.sh <dir>`. Replace `<dir>` with the path
   to where the conda environment should be installed.
4. Activate the environment by running `conda activate <dir>` (Note: `<dir>` 
   needs to be the absoultue path to the installed environment)

Requirements:
 - Linux 
 - Python 3
 - requests (pip3 install requests)
 - conda (anaconda3 or miniconda3)


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
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=./bin -DSEAL_THROW_ON_TRANSPARENT_CIPHERTEXT=OFF
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


