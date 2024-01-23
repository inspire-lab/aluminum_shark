# Tensforflow Plugin

## Description

Pluggable device for HE that hooks into Tensorflow.

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)


## Installation

To build and install the plugin project, follow these steps. All the step assume
that you are running them from this directory

1. Install and activate the conda environment:

  ```shell
  conda env create -f environment.yml
  conda activate shark_v2
  ```

2. Create the `Makefile.vars` by running:

  ```shell
  python create_makefile_vars.py
  ```

3. Build the plugin:

  ```shell
  make
  ```

4. (Optional and currently broken) Install the plugin. Since installing doesn't
work at the moment. Mostly because I don't know where to put the plugin, we need
to set the plugin environment variable `TF_PLUGGABLE_DEVICE_LIBRARY_PATH` before importing Tensorflow (see `main.py`):

  ```shell
  make install
  ```

## Usage

`main.py` contains a code stub that loads the plugin into tensorflow and checks 
that it was loaded correctly.


