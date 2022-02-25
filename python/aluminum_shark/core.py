import uuid
import warnings
import os
import ctypes
import tensorflow as tf
from typing import Union, List, Iterable
from inspect import currentframe, stack
import numpy as np


class EncryptedExecution():

  def __init__(self, model_fn, *args, **kwargs) -> None:
    with tf.device("/device:XLA_HE:0"):
      self.__model = model_fn(*args, **kwargs)

      @tf.function(jit_compile=True)
      def f(*args):
        return self.__model(*args)

      self.__func = f

  def __call__(self, *args) -> 'Ciphertext':

    assert (all([isinstance(x, CipherText) for x in args]))
    set_ciphertexts(args)

    # generate dummy inputs
    with tf.device("/device:XLA_HE:0"):
      dummies = [tf.convert_to_tensor(np.ones(x.shape)) for x in args]
      # print(dummies)
      self.__func(*dummies)
    return get_ciphertexts()


# TODO: remove


def encrypted_execution(
    func,
    model_fn,
    model_fn_args=(),
):

  def inner(*args, **kwargs):
    with tf.device("/device:XLA_HE:0"):
      model = model_fn(*model_fn_args)

    @tf.function(jit_compile=True)
    def f(*args):
      model(*args)

  return inner


def AS_LOG(*args, **kwargs):
  """
  Loggin function. Logs the filename and line it was called from. `args` and 
  `kwargs` are forwarded to `print`.
  """
  cf = currentframe()
  print("Aluminum Shark:", f"{stack()[1][1]}:{cf.f_back.f_lineno}" + "]", *args,
        **kwargs)


__DEFAULT_BACKEND__ = os.path.join(os.path.dirname(__file__),
                                   'aluminum_shark_seal.so')
AS_LOG('default backend: ', __DEFAULT_BACKEND__)

# get the tensorflow shared library path
tf_dir = tf.__file__[:-12]  # strip away file name '__init__.py'
tf_lib_path = os.path.join(tf_dir, 'python', '_pywrap_tensorflow_internal.so')
if not os.path.exists(tf_lib_path):
  raise Exception('Unable to find TensorFlow shared library ' + tf_lib_path)

# load the library and functions
tf_lib = ctypes.CDLL(tf_lib_path)
AS_LOG("Wrapped TensorFlow library: " + tf_lib_path)

############################
# backend functions        #
############################

# load and destroy backend
load_backend_func = tf_lib.aluminum_shark_loadBackend
load_backend_func.argtypes = [ctypes.c_char_p]
load_backend_func.restype = ctypes.c_void_p

destroy_backend_func = tf_lib.aluminum_shark_destroyBackend
destroy_backend_func.argtypes = [ctypes.c_void_p]

# create and destroy context

# ckks
create_backend_ckks_func = tf_lib.aluminum_shark_CreateContextCKKS
create_backend_ckks_func.argtypes = [
    ctypes.c_size_t,  # poly_modulus_degree
    ctypes.POINTER(ctypes.c_int),  # a list containing the coeff_modulus
    ctypes.c_int,  # number of moduli in the coeff_modulus list
    ctypes.c_double,  # scale
    ctypes.c_void_p  # backend handle
]
create_backend_ckks_func.restype = ctypes.c_void_p

# bfv
create_backend_bfv_func = tf_lib.aluminum_shark_CreateContextBFV
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
create_backend_tfhe_func = tf_lib.aluminum_shark_CreateContextTFHE
create_backend_tfhe_func.argtypes = [
    ctypes.c_void_p  # backend handle
]
create_backend_tfhe_func.restype = ctypes.c_void_p

############################
# context functions        #
############################

# key managment
create_pub_key_func = tf_lib.aluminum_shark_CreatePublicKey
create_pub_key_func.argtypes = [ctypes.c_void_p]

create_priv_key_func = tf_lib.aluminum_shark_CreatePrivateKey
create_priv_key_func.argtypes = [ctypes.c_void_p]

# TODO: saving and loading keys.
save_pub_key_func = tf_lib.aluminum_shark_SavePublicKey
save_pub_key_func.argtypes = [ctypes.c_char_p, ctypes.c_void_p]

save_priv_key_func = tf_lib.aluminum_shark_SavePrivateKey
save_priv_key_func.argtypes = [ctypes.c_char_p, ctypes.c_void_p]

load_pub_key_func = tf_lib.aluminum_shark_LoadPublicKey
load_pub_key_func.argtypes = [ctypes.c_char_p, ctypes.c_void_p]

load_priv_key_func = tf_lib.aluminum_shark_LoadPrivateKey
load_priv_key_func.argtypes = [ctypes.c_char_p, ctypes.c_void_p]

# encryption and decryption
encrypt_long_func = tf_lib.aluminum_shark_encryptLong
encrypt_long_func.argtypes = [
    ctypes.POINTER(ctypes.c_long),  # plaintexts
    ctypes.c_int,  # number of plaintexts
    ctypes.c_char_p,  # name
    ctypes.c_void_p  # context handle
]
encrypt_long_func.restype = ctypes.c_void_p

decrypt_long_func = tf_lib.aluminum_shark_decryptLong
decrypt_long_func.argtypes = [
    ctypes.POINTER(ctypes.c_long),  # pointer to decrypted plain texts
    ctypes.POINTER(ctypes.c_int),  # number of decrypted plain texts
    ctypes.c_void_p,  # ctxt handle
    ctypes.c_void_p  # context handle
]

encrypt_double_func = tf_lib.aluminum_shark_encryptDouble
encrypt_double_func.argtypes = [
    ctypes.POINTER(ctypes.c_double),  # plaintexts
    ctypes.c_int,  # number of plaintexts
    ctypes.c_char_p,  # name
    ctypes.c_void_p  # context handle
]
encrypt_double_func.restype = ctypes.c_void_p

decrypt_double_func = tf_lib.aluminum_shark_decryptDouble
decrypt_double_func.argtypes = [
    ctypes.POINTER(ctypes.c_double),  # plaintexts
    ctypes.POINTER(ctypes.c_int),  # number of plaintexts
    ctypes.c_void_p,  # ctxt handle
    ctypes.c_void_p  # context handle
]

number_of_slots_func = tf_lib.aluminum_shark_numberOfSlots
number_of_slots_func.argtypes = [
    ctypes.c_void_p  # context handle
]
number_of_slots_func.restype = ctypes.c_size_t

destroy_context_func = tf_lib.aluminum_shark_DestroyContext
destroy_context_func.argtypes = [ctypes.c_void_p]

# others

destroy_ctxt_func = tf_lib.aluminum_shark_DestroyCiphertext
destroy_ctxt_func.argtypes = [ctypes.c_void_p]

# ctxt retrieval
get_result_func = tf_lib.aluminum_shark_GetChipherTextResult
destroy_ctxt_func.argtypes = [ctypes.POINTER(ctypes.c_void_p)]
get_result_func.restype = ctypes.c_void_p


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

  def register_object(self, object) -> None:
    """
    Register `object` to be destroyed before `self` is destroyed.
    """
    self.objects.add(object)
    if self.parent is not None:
      self.parent.register(object)

  def remove_object(self, object) -> None:
    """
    Remove `object` from the list of objects that need to be destroyed together 
    with this object.
    """
    if object in self.objects:
      self.objects.remove(object)
    if self.parent is not None:
      self.parent.remove(object)

  def destroy(self) -> None:
    """
    Calls destroy on all registerd objects and removes itself from parent.
    """
    if self.parent is not None:
      self.parent.remove(self)
    for o in self.objects:
      o.destroy()


# Wraps around a ciphertext
class CipherText(ObjectCleaner):
  """
  A ciphertext object. It is valid as long as its `_handle` is not `None`. 
  """

  def __init__(self, handle: ctypes.c_void_p, context: "Context",
               shape: Iterable[int]) -> None:
    super().__init__(parent=context)
    self.__handle = handle
    self.__context = context
    self.__shape = shape

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
    return self.__shape

  def destroy(self) -> None:
    """
    Cleans up the ressources used by the ciphertext. Leaves it in an unuseable
    state.
    """
    super().destroy()
    tf_lib.aluminum_shark_DestroyCiphertext(self.__handle)
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

  def encrypt(self,
              ptxt: List[Union[int, float]],
              name: Union[None, str] = None,
              dtype=None,
              shape: Union[None, Iterable[int]] = None) -> CipherText:
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
    print(ptxt_ptr)

    # convert name
    name_arg = ctypes.c_char_p(str.encode(name))
    ctxt_handle = __enc_func(ptxt_ptr, len(ptxt), name_arg, self.__handle)
    return CipherText(handle=ctxt_handle, context=self, shape=shape)

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
                         dtype) -> Union[List[float], List[int]]:
    if dtype == int:
      ret = (ctypes.c_long * self.n_slots)(*list(range(self.n_slots)))
    elif dtype == float:
      ret = (ctypes.c_double * self.n_slots)(*list(range(self.n_slots)))
    else:
      raise ValueError("Data type needs to be float or int")
    ret_ptr = ctypes.pointer(ret)
    ret_size = ctypes.c_int(-1)
    ret_size_ptr = ctypes.pointer(ret_size)
    AS_LOG("Calling decryption function,", decrypt_func.argtypes)
    decrypt_func(ret, ret_size_ptr, ctxt._handle, self.__handle)
    return list(ret[:ret_size.value])

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
    tf_lib.aluminum_shark_DestroyContext(self.__handle)
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

  def destroy(self) -> None:
    super().destroy()
    destroy_backend_func(self.__handle)
    self.__handle = None

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

  def __repr__(self) -> str:
    return super().__repr__() + " handle: " + hex(self.__handle)


def debug_on(flag: bool) -> None:
  os.environ['ALUMINUM_SHARK_LOGGING'] = "1" if flag else "0"


def set_ciphertexts(ctxts: Union[CipherText, List[CipherText]]) -> None:
  """
  Set ciphertexts to be used in the next computation.
  """
  # check if we deal with a list
  try:
    _ = (e for e in ctxts)
  except TypeError:
    ctxts = [ctxts]
  ctxt_ptr_t = ctypes.c_void_p * len(ctxts)
  arg = ctxt_ptr_t(*[c._handle for c in ctxts])
  tf_lib.aluminum_shark_SetChipherTexts(arg, len(arg))


def get_ciphertexts() -> CipherText:
  """
  Retrieve the result of the last compuation. If no computation has been 
  performed the behaviour of this funtion is undefined.
  """
  # print("aluminum_shark.get_ciphertexts")
  context_ptr = ctypes.c_void_p()
  print(context_ptr)
  # print(context_ptr.contents)
  print(context_ptr.value)
  # print(hex(context_ptr.value))
  ctxt_handle = get_result_func(ctypes.byref(context_ptr))
  print(Context.context_map)
  print(context_ptr)
  print(hex(context_ptr.value))
  context = Context.find_context(context_ptr.value)
  return CipherText(handle=ctxt_handle, context=context,
                    shape=None)  # FIXME: shape information
