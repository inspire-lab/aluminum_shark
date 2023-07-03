import os


class config(object):

  @classmethod
  def create_config(cls, **kwargs):
    global current_config
    python_api_so = kwargs['python_api_so']
    current_config = cls(python_api_so)
    return current_config

  def __init__(self, python_api_so) -> None:
    self._python_api_so = python_api_so

  def PY_HANDLE_SHARED_LIB(self):
    return self._python_api_so


class tf_config(object):

  def PY_HANDLE_SHARED_LIB(self):
    import tensorflow as tf
    # get the tensorflow directory
    tf_dir = tf.__file__[:-12]  # strip away file name '__init__.py'

    # .so file that containts the py_handle functions. defaults to tensorflow .so
    return os.path.join(tf_dir, 'python', '_pywrap_tensorflow_internal.so')


current_config = tf_config()