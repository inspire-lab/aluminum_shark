# Install In Colab
- Download the latest release files from: https://github.com/inspire-lab/aluminum_shark/releases/
- Upload both files to Colab
- Run the following code in your first cell:
```
!pip install --no-deps --force-reinstall tensorflow-2.7.0-cp38-cp38-linux_x86_64.whl 
!tar -xvf aluminum_shark.tar
!pip3 install -e aluminum_shark/
!pip install keras==2.6.0
import os 
os.environ['TF_XLA_FLAGS'] = '--tf_xla_enable_xla_devices'
import tensorflow as tf
import numpy as np
import aluminum_shark.core as shark
```


