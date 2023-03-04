# !/bin/bash

# check if args are set correclty
ENV_DIR=$1
if [ -z ${ENV_DIR} ]; then
  echo "need to sepcify a directory to install the environment in."
  echo "usage: install_conda_environment.sh directory (conda_dir)"
  exit 1
fi

ENV_DIR=`readlink -f ${ENV_DIR}`

# get script dir
DIR=$( dirname -- "$0"; )

# check if we have conda
conda &> /dev/null

if [ $? -ne 0 ]; then
  echo "conda not installed. install conda"
  exit 1
fi

CONDA_SRIPT=""
# check if we can guess the conda path
if [ -f ~/miniconda3/etc/profile.d/conda.sh ]; then
  CONDA_SRIPT=~/miniconda3/etc/profile.d/conda.sh
elif [ -f ~/anaconda3/etc/profile.d/conda.sh ]; then
  CONDA_SRIPT=~/anaconda3/etc/profile.d/conda.sh
elif [ -z $2 ]; then
  echo "could not find the conda install directory. defaults are: ~/miniconda3 and ~/anaconda3 . you need to pass it as an addtional argument"
  echo "usage: install_conda_environment.sh directory conda_dir"
else
  CONDA_SRIPT=$2/etc/profile.d/conda.sh
fi

# download the assets files
python3 ${DIR}/asset_downloader.py
if [ $? -ne 0 ]; then
  echo "package download failed"
  exit 1
fi

# create conda environment
conda env create --prefix ${ENV_DIR} -f ${DIR}/environment.yml
if [ $? -ne 0 ]; then
  echo "couldn't create enviroment"
  exit 1
fi

# activate the environment
source ${CONDA_SRIPT}
if [ $? -ne 0 ]; then
  echo "couldnt source script at:"
  echo ${CONDA_SRIPT}
  exit 1
fi

conda activate ${ENV_DIR}
if [ $? -ne 0 ]; then
  echo "couldn't activate enviroment"
  exit 1
fi

# install custom tensorflow 
python3 -m pip install ${DIR}/install_files/tensorflow-2.7.0-cp38-cp38-linux_x86_64.whl
if [ $? -ne 0 ]; then
  echo "tensforflow install failed"
  exit 1
fi

# fix numpy version
python3 -m pip install numpy==1.21.2
if [ $? -ne 0 ]; then
  echo "numpy install failed"
  exit 1
fi

# install model optimization
python3 -m pip install tensorflow-model-optimization
if [ $? -ne 0 ]; then
  echo "tensorflow-model-optimization install failed"
  exit 1
fi

# unpack and install aluminum shark python package
tar -xvf ${DIR}/install_files/aluminum_shark.tar -C ${DIR}/install_files/
if [ $? -ne 0 ]; then
  echo "aluminum shark untar failed"
  exit 1
fi
python3 -m pip install -e ${DIR}/install_files/aluminum_shark/
if [ $? -ne 0 ]; then
  echo "aluminum shark install failed"
  exit 1
fi


conda deactivate


