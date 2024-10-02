import uuid
import os
import ctypes
import tensorflow as tf
from typing import Union, List, Iterable
from inspect import currentframe, stack
import numpy as np
from aluminum_shark import config
from aluminum_shark.c_arguments import aluminum_shark_Argument, get_argument_type
import time
import copy
import datetime

CRITICAL = 50
ERROR = 40
WARNING = 30
INFO = 20
DEBUG = 10

__log_level = 50


def AS_LOG(*args, hex_pointers=True, log_level=WARNING, **kwargs):
  """
  Loggin function. Logs the filename and line it was called from. `args` and 
  `kwargs` are forwarded to `print`.
  """
  if (__log_level >= log_level):
    return
  args = list(args)
  if hex_pointers:
    for i in range(len(args)):
      if isinstance(args[i], ctypes.c_void_p):
        args[i] = str(args[i]) + '; ' + str(hex(args[i].value))

  cf = currentframe()
  print("Aluminum Shark:", f"{stack()[1][1]}:{cf.f_back.f_lineno}" + "]", *args,
        **kwargs)


__DEFAULT_BACKEND__ = os.path.join(os.path.dirname(__file__),
                                   'aluminum_shark_seal.so')
SEAL_BACKEND = os.path.join(os.path.dirname(__file__), 'aluminum_shark_seal.so')
OPENFHE_BACKEND = os.path.join(os.path.dirname(__file__),
                               'aluminum_shark_openfhe.so')
AS_LOG('default backend: ', __DEFAULT_BACKEND__)

# get the tensorflow shared library path
so_path = config.current_config.PY_HANDLE_SHARED_LIB()
if not os.path.exists(so_path):
  raise Exception('Unable to find shared library ' + so_path)

# load the library and functions
python_api_lib = ctypes.CDLL(so_path)
AS_LOG("Wrapped TensorFlow library: " + so_path)

is_standalone = False
try:
  standalone_check = python_api_lib.aluminum_shark_isStandalone
  standalone_check.restype = ctypes.c_bool
  is_standalone = bool(standalone_check())
except:
  pass

############################
# backend functions        #
############################

# // struct to transport data between python and c++.
# struct Argument {
#   const char* name;
#   // 0: int
#   // 1: double
#   // 3: string
#   uint type;

#   // if true the `array_` member will point to an array containing `size_`
#   // elements of `type`.
#   bool is_array = false;

#   // data holding variables
#   long int_;
#   double double_;
#   const char* string_;
#   // holds data if `is_array` == ture.
#   void* array_ = nullptr;
#   size_t size_;
# };

# load and destroy backend
load_backend_func = python_api_lib.aluminum_shark_loadBackend
load_backend_func.argtypes = [ctypes.c_char_p]
load_backend_func.restype = ctypes.c_void_p

destroy_backend_func = python_api_lib.aluminum_shark_destroyBackend
destroy_backend_func.argtypes = [ctypes.c_void_p]

# turn on the ressource monitoring
# void aluminum_shark_enable_ressource_monitor(bool enable, void* backend_ptr);
enable_ressource_monitor_func = python_api_lib.aluminum_shark_enable_ressource_monitor
enable_ressource_monitor_func.argtypes = [ctypes.c_bool, ctypes.c_void_p]

# create and destroy context

# ckks
create_backend_ckks_func = python_api_lib.aluminum_shark_CreateContextCKKS
create_backend_ckks_func.argtypes = [
    ctypes.c_size_t,  # poly_modulus_degree
    ctypes.POINTER(ctypes.c_int),  # a list containing the coeff_modulus
    ctypes.c_int,  # number of moduli in the coeff_modulus list
    ctypes.c_double,  # scale
    ctypes.c_void_p  # backend handle
]
create_backend_ckks_func.restype = ctypes.c_void_p

# bfv
create_backend_bfv_func = python_api_lib.aluminum_shark_CreateContextBFV
create_backend_bfv_func.argtypes = [
    ctypes.c_size_t,  # poly_modulus_degree
    ctypes.POINTER(ctypes.c_int),  # a list containing the coeff_modulus
    ctypes.c_int,  # number of moduli in the coeff_modulus list
    ctypes.c_double,  # plain modulus
    ctypes.c_void_p  # backend handle
]
create_backend_bfv_func.restype = ctypes.c_void_p

# tfhe
# TODO:
create_backend_tfhe_func = python_api_lib.aluminum_shark_CreateContextTFHE
create_backend_tfhe_func.argtypes = [
    ctypes.c_void_p  # backend handle
]
create_backend_tfhe_func.restype = ctypes.c_void_p

create_backend_ckks_dynamic_func = python_api_lib.aluminum_shark_CreateContextCKKS_dynamic
create_backend_ckks_dynamic_func.argtypes = [
    ctypes.POINTER(aluminum_shark_Argument),  # array of arguments
    ctypes.c_int,  # number of arguments
    ctypes.c_void_p  # backend pointer
]
create_backend_ckks_dynamic_func.restype = ctypes.c_void_p

############################
# context functions        #
############################

# key managment
create_pub_key_func = python_api_lib.aluminum_shark_CreatePublicKey
create_pub_key_func.argtypes = [ctypes.c_void_p]

create_priv_key_func = python_api_lib.aluminum_shark_CreatePrivateKey
create_priv_key_func.argtypes = [ctypes.c_void_p]

# TODO: saving and loading keys.
save_pub_key_func = python_api_lib.aluminum_shark_SavePublicKey
save_pub_key_func.argtypes = [ctypes.c_char_p, ctypes.c_void_p]

save_priv_key_func = python_api_lib.aluminum_shark_SavePrivateKey
save_priv_key_func.argtypes = [ctypes.c_char_p, ctypes.c_void_p]

load_pub_key_func = python_api_lib.aluminum_shark_LoadPublicKey
load_pub_key_func.argtypes = [ctypes.c_char_p, ctypes.c_void_p]

load_priv_key_func = python_api_lib.aluminum_shark_LoadPrivateKey
load_priv_key_func.argtypes = [ctypes.c_char_p, ctypes.c_void_p]

# encryption and decryption

# int
# void* aluminum_shark_encryptLong(const long* values, int size, const char* name,
#                                  const size_t* shape, int shape_size,
#                                  const char* layout, void* context_ptr)
encrypt_long_func = python_api_lib.aluminum_shark_encryptLong
encrypt_long_func.argtypes = [
    ctypes.POINTER(ctypes.c_long),  # plaintexts
    ctypes.c_int,  # number of plaintexts
    ctypes.c_char_p,  # name
    ctypes.POINTER(ctypes.c_size_t),  # shape
    ctypes.c_int,  # rank of the data
    ctypes.c_char_p,  # layout 
    ctypes.c_void_p  # context handle
]
encrypt_long_func.restype = ctypes.c_void_p

decrypt_long_func = python_api_lib.aluminum_shark_decryptLong
decrypt_long_func.argtypes = [
    ctypes.POINTER(ctypes.c_long),  # pointer to decrypted plain texts
    ctypes.c_void_p,  # ctxt handle
    ctypes.c_void_p  # context handle
]

# float
# void* aluminum_shark_encryptDouble(const double* values, int size,
#                                    const char* name, const size_t* shape,
#                                    int shape_size, const char* layout,
#                                    void* context_ptr)
encrypt_double_func = python_api_lib.aluminum_shark_encryptDouble
encrypt_double_func.argtypes = [
    ctypes.POINTER(ctypes.c_double),  # plaintexts
    ctypes.c_int,  # number of plaintexts
    ctypes.c_char_p,  # name
    ctypes.POINTER(ctypes.c_size_t),  # shape
    ctypes.c_int,  # rank of the data
    ctypes.c_char_p,  # layout 
    ctypes.c_void_p  # context handle
]
encrypt_double_func.restype = ctypes.c_void_p

# see if the api supports multithreaded encryption. only really needed in
# standalone
try:
  # void aluminum_shark_encryptDouble_mt(const double* values, int size,
  #                                    const char* name, const size_t* shape,
  #                                    int shape_size, const char* layout_type,
  #                                    void* return_array, void* context_ptr)
  encrypt_double_func_mt = python_api_lib.aluminum_shark_encryptDouble_mt
  encrypt_double_func_mt.argtypes = [
      ctypes.POINTER(ctypes.c_double),  # plaintexts
      ctypes.c_int,  # number of plaintexts
      ctypes.c_char_p,  # name
      ctypes.POINTER(ctypes.c_size_t),  # shape
      ctypes.c_int,  # rank of the data
      ctypes.c_char_p,  # layout 
      ctypes.c_void_p,  # return array, needs to be inalized to hold the 
      # ciphertext handles
      ctypes.c_void_p  # context handle
  ]
except:
  encrypt_double_func_mt = None

decrypt_double_func = python_api_lib.aluminum_shark_decryptDouble
decrypt_double_func.argtypes = [
    ctypes.POINTER(ctypes.c_double),  # plaintexts
    ctypes.c_void_p,  # ctxt handle
    ctypes.c_void_p  # context handle
]

number_of_slots_func = python_api_lib.aluminum_shark_numberOfSlots
number_of_slots_func.argtypes = [
    ctypes.c_void_p  # context handle
]
number_of_slots_func.restype = ctypes.c_size_t

destroy_context_func = python_api_lib.aluminum_shark_DestroyContext
destroy_context_func.argtypes = [ctypes.c_void_p]

############################
# computation functions    #
############################

# ctxt callback function
# void* aluminum_shark_RegisterComputation(void* (*ctxt_callback)(int*),
#                                          void (*result_callback)(void*, int),
#                                          void (*monitor_value_callback)(const char*, double),
#                                          void (*monitor_progress_callback)(const char*, bool),
#                                          const char* forced_layout,
#                                          bool clear_memory);
ctxt_callback_type = ctypes.CFUNCTYPE(ctypes.c_void_p,
                                      ctypes.POINTER(ctypes.c_int))
result_callback_type = ctypes.CFUNCTYPE(None, ctypes.POINTER(ctypes.c_void_p),
                                        ctypes.c_int)
monitor_value_callback_type = ctypes.CFUNCTYPE(None, ctypes.c_char_p,
                                               ctypes.c_double)
monitor_progress_callback_type = ctypes.CFUNCTYPE(None, ctypes.c_char_p,
                                                  ctypes.c_bool)
if not is_standalone:
  register_computation_func = python_api_lib.aluminum_shark_RegisterComputation
  register_computation_func.argtypes = [
      ctxt_callback_type, result_callback_type, monitor_value_callback_type,
      monitor_progress_callback_type, ctypes.c_char_p, ctypes.c_bool
  ]
  register_computation_func.restype = ctypes.c_void_p

############################
# layout functions         #
############################

# const char** aluminum_shark_GetAvailabeLayouts(size_t* size)
get_avalailabe_layouts_func = python_api_lib.aluminum_shark_GetAvailabeLayouts
get_avalailabe_layouts_func.argtypes = [ctypes.POINTER(ctypes.c_size_t)]
get_avalailabe_layouts_func.restype = ctypes.POINTER(ctypes.c_char_p)

############################
# ciphertext functions     #
############################

destroy_ctxt_func = python_api_lib.aluminum_shark_DestroyCiphertext
destroy_ctxt_func.argtypes = [ctypes.c_void_p]

get_ctxt_shape_len_func = python_api_lib.aluminum_shark_GetCtxtShapeLen
get_ctxt_shape_len_func.argtypes = [ctypes.c_void_p]
get_ctxt_shape_len_func.restype = ctypes.c_size_t

get_ctxt_shape_func = python_api_lib.aluminum_shark_GetCtxtShape
get_ctxt_shape_func.argtypes = [
    ctypes.c_void_p, ctypes.POINTER(ctypes.c_size_t)
]

############################
# others
############################

# turns logging on or off
# void aluminum_shark_EnableLogging(bool on);
enable_logging_func = python_api_lib.aluminum_shark_EnableLogging
enable_logging_func.argtypes = [ctypes.c_bool]

# sets the log level
# void aluminum_shark_SetLogLevel(int level);
set_log_level_func = python_api_lib.aluminum_shark_SetLogLevel
set_log_level_func.argtypes = [ctypes.c_int]

# sets the backend log level
# void aluminum_shark_SetBackendLogLevel(int level);
set_backend_log_level_func = python_api_lib.aluminum_shark_SetBackendLogLevel
set_backend_log_level_func.argtypes = [ctypes.c_int, ctypes.c_void_p]


class ObjectCleaner(object):
  """
  Interface for registering objects and cleaning up objects.

  If a `parent` is specified it should also be an instance of `ObjectCleaner`. 
  In this case the cleanup will happen recursivly.
  """

  def __init__(self, parent=None) -> None:
    # super().__init__()
    self.objects = set()
    self.parent = parent
    if parent is not None:
      parent.register_object(self)

  def register_object(self, object) -> None:
    """
    Register `object` to be destroyed before `self` is destroyed.
    """
    self.objects.add(object)
    # if self.parent is not None:
    #   self.parent.register(object)

  def remove_object(self, object) -> None:
    """
    Remove `object` from the list of objects that need to be destroyed together 
    with this object.
    """
    if object in self.objects:
      self.objects.remove(object)
    if self.parent is not None:
      self.parent.remove_object(object)

  def destroy(self) -> None:
    """
    Calls destroy on all registerd objects and removes itself from parent.
    """
    if self.parent is not None:
      self.parent.remove_object(self)
    while self.objects:
      o = self.objects.pop()
      o.destroy()


class CallbackHandler(object):

  def __init__(self, show_hlo_progress=True) -> None:
    self.show_hlo_progress = show_hlo_progress
    self.history = {}
    self.op_history = []
    self.__current_object = {}
    self.__progress = 0

    def value_callback(name: ctypes.c_char_p, value: ctypes.c_double):
      name = bytes.decode(name)
      if name not in self.history:
        self.history[name] = [value]
      else:
        self.history[name].append(value)
      self.__current_object[name] = value

    self.c_value_callback = monitor_value_callback_type(value_callback)

    def progress_callback(name: ctypes.c_char_p, start: ctypes.c_bool):
      """
      Get's called with true when and operation starts and with false when it 
      ends
      """
      name = bytes.decode(name)
      if start:
        start_t = time.time()
        self.op_history.append({'start': start_t, 'op': name, 'before': {}})
        self.__current_object = self.op_history[-1]['before']
        if self.show_hlo_progress:
          print(f'{self.__progress}/? started computing: ', name,
                self.__current_object)
      else:
        end_t = time.time()
        self.op_history[-1]['end'] = end_t
        self.op_history[-1]['after'] = {}
        self.__current_object = self.op_history[-1]['after']
        self.__progress += 1
        if self.show_hlo_progress:
          print(
              'done computing: {} time elapsed: {:.2f} seconds'.format(
                  name,
                  self.op_history[-1]['end'] - self.op_history[-1]['start']),
              self.__current_object)

    self.c_progress_callback = monitor_progress_callback_type(progress_callback)

  def compile_history(self, clear_no_ciphertext_ops=False):
    """
    Compiles the recorded history. If `clear_no_ciphertext_ops` hlos that have 
    likely ciphertext involvement are ommited.
    """
    compiled_history = {}
    op_history = []
    # compile the date from the hlo operations
    for entry in self.op_history:
      d = copy.deepcopy(entry)
      d['time'] = d['end'] - d['start']
      include_op = False
      for key in d['before']:
        if key not in d['after']:
          print(F'`{key}` missing')
          d[key] = d['before'][key]
          continue
        d[key] = d['after'][key] - d['before'][key]
        # if all differences are 0 we can assume that no ciphertext was invlolved
        include_op = include_op or d[key] != 0
      if not clear_no_ciphertext_ops or include_op:
        op_history.append(d)
    compiled_history['hlos'] = op_history

    # set start and end time
    compiled_history['start_time'] = datetime.datetime.fromtimestamp(
        self.op_history[0]['start']).strftime('%Y-%m-%d-%H-%M-%S')
    compiled_history['end_time'] = datetime.datetime.fromtimestamp(
        self.op_history[0]['end']).strftime('%Y-%m-%d-%H-%M-%S')

    # compute totals
    total_ctxt_operations = 0
    for key in self.history:
      compiled_history['total_' + key] = self.history[key][-1]
      total_ctxt_operations += self.history[key][-1]
    compiled_history['total_ciphertext_operations'] = total_ctxt_operations

    return compiled_history


class EncryptedExecution(ObjectCleaner):

  def __init__(self,
               context,
               model_fn,
               forced_layout: str = None,
               clear_memory: bool = False,
               show_progress: bool = False,
               *args,
               **kwargs) -> None:
    """
    Create an EncryptedExecution instance. 

    Args:
      context (Context): The crypto context
      model_fn (callable): Function that returns a model 
      forced_layout (str): Layout to use during execution
      clear_memory (bool): Clear intermediate results. WARNING: settting it to
                           true will also consume and invalidate the inputs to
                           __call__ after it returns.
      show_progress: bool = False,
    """
    super().__init__(parent=context)
    with tf.device("/device:XLA_HE:0"):
      self.__model = model_fn(*args, **kwargs)
      self.context = context

      @tf.function(jit_compile=True)
      @tf.autograph.experimental.do_not_convert
      def f(*args):
        return self.__model(*args)

      self.__func = f

    self.__ctxt_inputs = None

    def ctxt_callback(num: ctypes.POINTER(ctypes.c_int)) -> ctypes.c_void_p:
      """
      Callback that is called from C++ once the computation is started. The 
      number of handles needs to be written into `num` 
      pointer.

      Returns a pointer to the input array
      """
      AS_LOG('ctxt callback called with:', num)
      if self.__ctxt_inputs is None:
        ValueError(
            'ctxt callback has been called before ciphertexts have been set')
      array_t = ctypes.c_void_p * len(self.__ctxt_inputs)
      ret = array_t(*[c._handle for c in self.__ctxt_inputs])
      ret = ctypes.cast(ret, ctypes.c_void_p)
      num_ct = ctypes.c_int(len(self.__ctxt_inputs))
      num[0] = len(self.__ctxt_inputs)
      AS_LOG('c_void_p -> array', ret)
      AS_LOG('returning callback:', ret, 'num', num, '*num', num.contents)
      return ret.value

    self.__ctxt_call_back = ctxt_callback_type(ctxt_callback)

    self.result = None

    def result_callback(values: ctypes.c_void_p, size: ctypes.c_int):
      AS_LOG(self.__result_callback.argtypes)
      AS_LOG(self.__result_callback.restype)
      AS_LOG(type(values), type(size))
      AS_LOG('result_callback invoked. values', values, 'size', size)
      result_handles = values[:size]
      AS_LOG('results', result_handles)
      self.result = [
          CipherText(ctypes.c_void_p(handle), self.context, shape=None)
          for handle in result_handles
      ]  # FIX shape

    self.__result_callback = result_callback_type(result_callback)
    if forced_layout is not None:
      AS_LOG('creating computation with forecd laytou:', forced_layout)
      forced_layout = forced_layout.encode('utf-8')
      AS_LOG(forced_layout)
    else:
      AS_LOG('creating computation without forecd layout')

    # create the monitor callback handler
    self.__monitor = CallbackHandler(show_hlo_progress=show_progress)

    self.clear_memory = clear_memory

    self.__computation_handle = register_computation_func(
        self.__ctxt_call_back, self.__result_callback,
        self.__monitor.c_value_callback, self.__monitor.c_progress_callback,
        forced_layout, clear_memory)

    self.forced_layout = forced_layout

  def __call__(self,
               *args,
               debug_inputs: List[np.array] = None) -> 'Ciphertext':
    """
    Perform the encrypted execution.

    If `clear_memory` is `True` the inputs to this function will be invalidated
    and can not be at any point after calling this function.

    args:         encrypted inputs to the exectution
    debug_inputs: list of plain data numpy arrays that can be passed for plain 
                  debuging computation. The shape of the numpy arrays must match
                  the encyrtpted inputs in args.
    """

    assert (all([isinstance(x, CipherText) for x in args]))
    self.__ctxt_inputs = args
    # set_ciphertexts(args)

    # generate dummy inputs
    with tf.device("/device:XLA_HE:0"):
      if debug_inputs is not None:
        # saftey checks
        if len(args) != len(debug_inputs):
          raise RuntimeError(
              f'number of debug inputs ({len(debug_inputs)})' +
              f'needs to match number of ciphertext inputs({len(args)})')
        for i, (dbg, ctxt) in enumerate(zip(debug_inputs, args)):
          if dbg.shape != tuple(ctxt.shape):
            raise RuntimeError(f'argument and  debug input {i} shape mismatch' +
                               f'{tuple(ctxt.shape)} and {dbg.shape}')
        dummies = [tf.convert_to_tensor(x) for x in debug_inputs]
      else:
        dummies = [tf.convert_to_tensor(np.ones(x.shape)) for x in args]
      self.__func(*dummies)
    if self.clear_memory:
      for ctxt in self.__ctxt_inputs:
        # the C object is destroyed during computaiton
        ctxt.destroy(destroy_c_object=False)

    return self.result

  @property
  def monitor(self):
    return self.__monitor


# Wraps around a ciphertext
class CipherText(ObjectCleaner):
  """
  A ciphertext object. It is valid as long as its `_handle` is not `None`. 
  """

  def __init__(self,
               handle: ctypes.c_void_p,
               context: "Context",
               shape: Iterable[int],
               layout: str = None) -> None:
    super().__init__(parent=context)
    self.__handle = handle
    self.__context = context
    self.layout = layout

  @property
  def _handle(self):
    return self.__handle

  @property
  def context(self):
    """
    The context the ciphertext was created by.
    """
    return self.__context

  @property
  def shape(self):
    return self.__get_shape_internal()

  def __get_shape_internal(self):
    # find out the lenght of the shape
    lenght = get_ctxt_shape_len_func(self.__handle)
    AS_LOG('called get_ctxt_shape_len_func', lenght)
    # reserve space
    shape_array = (ctypes.c_size_t * lenght)(*[0] * lenght)
    AS_LOG('calling get_ctxt_shape_func with', shape_array)
    get_ctxt_shape_func(self.__handle, shape_array)
    AS_LOG('called get_ctxt_shape_func with. got shape', shape_array[:])
    return shape_array[:]

  def destroy(self, destroy_c_object=True) -> None:
    """
    Cleans up the ressources used by the ciphertext. Leaves it in an unuseable
    state.
    
    Args:
      destroy_c_object (bool): Destroys the underlying C object too. Should 
                               always be `True` unless the C object was 
                               already destroyed some other way

    """
    super().destroy()
    if destroy_c_object:
      python_api_lib.aluminum_shark_DestroyCiphertext(self.__handle)
    self.__handle = None

  def register_object(self, object) -> None:
    """
    Does nothing for Ciphertexts
    """
    pass


class Context(ObjectCleaner):
  """
  An HE context. Provides functions for encryption, decryption and key managment.
  Currently it does not know what plaintext space it supports. The encryption 
  method tries to infer the data type or it can be passed explicitly.

  At the moment there is no accesiable `Plaintext`.  
  """

  context_map = {}

  @staticmethod
  def find_context(handle):
    return Context.context_map[handle]

  def __init__(self, handle: ctypes.c_void_p, backend: "HEBackend") -> None:
    super().__init__(parent=backend)
    self.__handle = handle
    self.__n_slots = number_of_slots_func(self.__handle)
    self.__has_keys = False
    self.__has_pub_key = False
    self.__has_priv_key = False
    Context.context_map[handle] = self
    AS_LOG("Created Context", self)

  def standalone_multithead_encryption(self, data):
    if not is_standalone or encrypt_double_func_mt is None:
      raise Exception(
          'standalone_multithead_encryption not suppport by API implementaion')
    if not isinstance(data, np.ndarray):
      raise Exception(
          'standalone_multithead_encryption only excepts numpy arrayys')
    if len(data.shape) != 2:
      raise Exception(
          f'standalone_multithead_encryption needs exectly 2D data. Got shape {data.shape}'
      )

    # make sure data is in correct format
    if not data.flags['C_CONTIGUOUS'] or data.dtype != np.double:
      data = np.ascontiguousarray(data, dtype=np.double)

    # format shape
    shape_ptr = (ctypes.c_size_t * len(data.shape))(*data.shape)
    shape_size = len(data.shape)

    # encode strings:
    # convert name
    name_arg = 'ctxt'.encode('utf-8')
    # convert layout to byte array. ignored atm
    layout_c = ''.encode('utf-8')

    # convert input to pointers
    data_pointer = data.ctypes.data_as(ctypes.POINTER(ctypes.c_double))

    # create return array
    return_array = (ctypes.c_void_p *
                    len(data))(*[ctypes.c_void_p() for _ in range(len(data))])

    encrypt_double_func_mt(
        data_pointer,  #data ptxt_ptr,
        len(data),
        name_arg,
        shape_ptr,
        shape_size,
        layout_c,
        return_array,
        self.__handle)

    ctxts = [
        CipherText(handle=h, context=self, shape=data.shape[1], layout='batch')
        for h in return_array
    ]

    return ctxts

  def encrypt(self,
              ptxt: List[Union[int, float]],
              name: Union[None, str] = None,
              dtype=None,
              shape: Union[None, Iterable[int]] = None,
              layout: str = 'simple') -> CipherText:
    """
    Takes `list` of numbers as `ptxt` and encrypts it. It tries to infer the
    encoding from the passed plaintexts if `dtype` is `None`. If type inference 
    is used it will be `float` iff any value in `ptxt` is `float. Otherwise it
    they are all assumed to be of type `int`. Type inference can be disabled by 
    passing the desired type as `dtype`. This causes all values in `ptxt` to be
    cast to either `int` or `float`.

    A ciphertext can be given a name for debuggin purposes. If no name is passed
    a UUID will be generated.

    Returns: encrypted `Ciphertext`
    """
    if name is None:
      name = str(uuid.uuid1())

    if shape is None:
      if hasattr(ptxt, 'shape'):
        shape = ptxt.shape
      else:
        shape = (len(ptxt),)

    if hasattr(ptxt, 'reshape'):
      ptxt = ptxt.reshape(-1)

    # determine data type
    is_float = dtype == float or any([isinstance(x, float)
                                      for x in ptxt]) and dtype is None
    # convert ptxt list
    if is_float:
      ptxt = [float(x) for x in ptxt]
      ptxt_ptr_t = ctypes.c_double * len(ptxt)
      __enc_func = encrypt_double_func
    else:
      ptxt = [int(x) for x in ptxt]
      ptxt_ptr_t = ctypes.c_long * len(ptxt)
      __enc_func = encrypt_long_func
    ptxt_ptr = ptxt_ptr_t(*ptxt)

    # convert name
    name_arg = name.encode('utf-8')

    # create the layout
    shape_ptr = (ctypes.c_size_t * len(shape))(*shape)
    shape_size = len(shape)
    # convert layout to byte array
    layout_c = layout.encode('utf-8')

    ctxt_handle = __enc_func(ptxt_ptr, len(ptxt), name_arg, shape_ptr,
                             shape_size, layout_c, self.__handle)
    return CipherText(handle=ctxt_handle,
                      context=self,
                      shape=shape,
                      layout=layout)

  def decrypt_long(self, ctxt: CipherText) -> List[int]:
    """
    Decrypt the `ctxt` and decode it as `int`.
    """
    return self.__decrypt_internal(ctxt, decrypt_long_func, int)

  def decrypt_double(self, ctxt: CipherText) -> List[float]:
    """
    Decrypt the `ctxt` and decode it as `float`.
    """
    return self.__decrypt_internal(ctxt, decrypt_double_func, float)

  def __decrypt_internal(self, ctxt: CipherText, decrypt_func,
                         dtype) -> np.array:
    # get the shape to compute the size of the reutrn array
    shape = ctxt.shape
    size = 1
    for x in shape:
      size = size * x
    if dtype == int:
      ret = (ctypes.c_long * size)(*list(range(size)))
    elif dtype == float:
      ret = (ctypes.c_double * size)(*list(range(size)))
    else:
      raise ValueError("Data type needs to be float or int")
    # ret_ptr = ctypes.pointer(ret)
    AS_LOG("Calling decryption function,", decrypt_func.argtypes)
    decrypt_func(ret, ctxt._handle, self.__handle)
    ret_value = np.asarray(ret[:]).reshape(shape)
    return ret_value

  def create_keys(self) -> None:
    """
    Creates public and private key
    """
    self.create_public_key()
    self.create_private_key()

  def create_public_key(self) -> None:
    """
    Creates a public key. If a public key has already been created does nothing.
    """
    if self.__has_pub_key:
      return
    create_pub_key_func(self.__handle)
    self.__has_pub_key = True

  def create_private_key(self) -> None:
    """
    Creates a private key. If a private key has already been created does nothing.
    """
    if self.__has_priv_key:
      return
    create_priv_key_func(self.__handle)
    self.__has_priv_key = True

  @property
  def keys_created(self) -> bool:
    """
    True iff private and public have been created
    """
    return self.__has_pub_key and self.__has_priv_key

  @property
  def n_slots(self) -> int:
    """
    Returns the number of ciphertext slots supported by the context
    """
    return self.__n_slots

  def destroy(self) -> None:
    super().destroy()
    python_api_lib.aluminum_shark_DestroyContext(self.__handle)
    self.__handle = None

  def __repr__(self) -> str:
    return super().__repr__() + " handle: " + hex(
        self.__handle) + " keys: " + str(
            self.keys_created) + " n_slots: " + str(self.n_slots)


# A class encasuplating an HE backend
class HEBackend(ObjectCleaner):
  """
  An HEBackend. By default loads the SEAL backend.
  """

  def __init__(self, path: str = __DEFAULT_BACKEND__) -> None:
    super().__init__()
    if not os.path.exists(path):
      raise FileNotFoundError('Can\'t find backend shared library: ' + path)
    self._lib_path = path
    AS_LOG("loading backend at: ", self._lib_path)
    # load the backend
    path_arg = ctypes.c_char_p(str.encode(path))
    self.__handle = load_backend_func(path_arg)
    AS_LOG("Created backend", self)
    self.__layouts = None

  def destroy(self) -> None:
    super().destroy()
    destroy_backend_func(self.__handle)
    self.__handle = None

  def createContext(self, scheme=None, **kwargs):
    if scheme == 'ckks':
      args = [
          aluminum_shark_Argument(name=name, value=kwargs[name])
          for name in kwargs
      ]
      AS_LOG('Creating Context. Arguments:', args)

      args_list = (ctypes.POINTER(aluminum_shark_Argument) *
                   len(args))(*[ctypes.pointer(x) for x in args])

      handle = create_backend_ckks_dynamic_func(
          ctypes.cast(args_list, ctypes.POINTER(aluminum_shark_Argument)),
          len(args), self.__handle)
    else:
      raise RuntimeError('not implemented yet')

    return Context(handle, self)

  def createContextCKKS(self, poly_modulus_degree, coeff_modulus, scale):
    """
    Create a CKKS context
    - poly_modulus_degree (degree of polynomial modulus)
    - coeff_modulus ([ciphertext] coefficient modulus) list of moduli
    - scale
    """
    # convert coeff_modulus list
    coeff_modulus_ptr_t = ctypes.c_int * len(coeff_modulus)
    coeff_modulus_ptr = coeff_modulus_ptr_t(*coeff_modulus)

    AS_LOG('Creating context', create_backend_ckks_func,
           create_backend_ckks_func.argtypes, '->',
           create_backend_ckks_func.restype)

    handle = create_backend_ckks_func(poly_modulus_degree, coeff_modulus_ptr,
                                      len(coeff_modulus), scale, self.__handle)
    return Context(handle, self)

  def createContextBFV(self, poly_modulus_degree, coeff_modulus, plain_modulus):
    """
    Create a CKKS context
    - poly_modulus_degree (degree of polynomial modulus)
    - coeff_modulus ([ciphertext] coefficient modulus) list of moduli
    - plain_modulus (plaintext modulus)
    """
    # convert coeff_modulus list
    coeff_modulus_ptr_t = ctypes.c_int * len(coeff_modulus)
    coeff_modulus_ptr = coeff_modulus_ptr_t(*coeff_modulus)

    handle = create_backend_bfv_func(poly_modulus_degree, coeff_modulus_ptr,
                                     len(coeff_modulus), plain_modulus,
                                     self.__handle)

    return Context(handle, self)

  @property
  def handle(self):
    return self.__handle

  @property
  def layouts(self) -> List[str]:
    if self.__layouts is not None:
      return self.__layouts
    size = ctypes.c_size_t(0)
    layouts = get_avalailabe_layouts_func(ctypes.byref(size))
    size = size.value
    self.__layouts = [l.decode('utf-8') for l in layouts[:size]]
    return self.__layouts

  def set_log_level(self, level):
    __log_level = level
    set_backend_log_level_func(level, self.__handle)

  def __repr__(self) -> str:
    return super().__repr__() + " handle: " + hex(self.__handle)

  def enable_ressource_monitor(self, enable):
    """
    Turns the ressource monitor on or off.
    """
    enable_ressource_monitor_func(enable, self.__handle)


def debug_on(flag: bool) -> None:
  enable_logging_func(flag)


def enable_logging(flag: bool) -> None:
  enable_logging_func(flag)


def set_log_level(level: int) -> None:
  set_log_level_func(level)