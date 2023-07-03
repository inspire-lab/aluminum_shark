import ctypes
import numpy as np


def get_argument_type(obj):
  if isinstance(obj, (int, np.integer)):
    return 0
  elif isinstance(obj, (float, np.floating)):
    return 1
  elif isinstance(obj, str):
    return 2


class aluminum_shark_Argument(ctypes.Structure):
  _fields_ = [('name', ctypes.c_char_p), ('type', ctypes.c_uint),
              ('is_array', ctypes.c_bool), ('int_', ctypes.c_long),
              ('double_', ctypes.c_double), ('string_', ctypes.c_char_p),
              ('array_', ctypes.c_void_p), ('size_', ctypes.c_size_t)]

  def __init__(self, name, value) -> None:
    # default values
    name_ = name.encode('utf-8')
    is_array = False
    int_ = ctypes.c_long()
    double_ = ctypes.c_double()
    string_ = ctypes.c_char_p()
    array_ = ctypes.c_void_p()
    size_ = ctypes.c_size_t()

    # check if we are dealing with a "basic type"
    type_ = get_argument_type(value)

    # single value
    if type_ is not None:
      # int
      if type_ == 0:
        int_ = ctypes.c_long(int(value))
      # float
      elif type_ == 1:
        double_ = ctypes.c_double(float(value))
      # string
      elif type_ == 2:
        string_ = value.encode('utf-8')

    # possibly an array or something we can't handle
    else:
      # make sure that we deal with a list that has all the same type
      types = [get_argument_type(x) for x in value]
      # check that they are all the same
      if len(set(types)) > 1:
        raise ValueError("all list elments must have the same type")
      type_ = types[0]
      if type_ is None:
        raise ValueError("Unsupported datatype ", type(value[0]))
      # we are dealing with an array
      is_array = True

      # int
      if type_ == 0:
        ints = [int(x) for x in value]
        array_t = ctypes.c_long * len(ints)
        array_ = array_t(*ints)
      # float
      elif type_ == 1:
        floats = [float(x) for x in value]
        array_t = ctypes.c_double * len(floats)
        array_ = array_t(*floats)
      # string
      elif type_ == 2:
        strings = [x.encode('utf-8') for x in value]
        array_t = ctypes.c_double * len(ctypes.c_char_p)
        array_ = array_t(*strings)
      else:
        raise ValueError("unkown type ", type)

      # set size and cast array_ to void*
      size_ = ctypes.c_size_t(len(value))
      array_ = ctypes.cast(array_, ctypes.c_void_p)

    # set type_ and call the super constructor
    type_ = ctypes.c_uint(type_)

    super().__init__(name_, type_, is_array, int_, double_, string_, array_,
                     size_)

  def __str__(self) -> str:
    s = self.__repr__() + '\n'
    for f in self._fields_:
      attr_name = f[0]
      attr = getattr(self, attr_name)
      s += '  ' + attr_name + ': ' + str(attr) + '\n'
    return s


class ArgList(object):

  def __init__(self, d: dict) -> None:
    self.__list = [
        aluminum_shark_Argument(name=name, value=d[name]) for name in d
    ]
    self.__c_list = (ctypes.POINTER(aluminum_shark_Argument) *
                     len(self.__list))(
                         *[ctypes.pointer(x) for x in self.__list])
    self.__pointer = ctypes.cast(self.__c_list,
                                 ctypes.POINTER(aluminum_shark_Argument))

  def __len__(self):
    return len(self.__list)

  @property
  def pointer(self):
    return self.__pointer
