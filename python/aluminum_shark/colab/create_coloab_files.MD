# Create the files to run in TensorFlow

Build the Aluminum Shark TensorFlow package and grab the wheel file from
'/tmp/tensorflow_pkg/'


Package up the python code by running the following command from above the
project root:
```
tar -cvhf aluminum_shark.tar --exclude='test*' --exclude='*pycache*' --exclude='*egg*' aluminum_shark/setup.py aluminum_shark/python/
```

