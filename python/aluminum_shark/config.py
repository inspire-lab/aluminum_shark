import os
import tensorflow as tf

# get the tensorflow directory
tf_dir = tf.__file__[:-12]  # strip away file name '__init__.py'

# .so file that containts the py_handle functions. defaults to tensorflow .so
PY_HANDLE_SHARED_LIB = os.path.join(tf_dir, 'python',
                                    '_pywrap_tensorflow_internal.so')
