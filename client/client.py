import os
os.environ['ALUMINUM_SHARK_LOGGING'] = '1'
from logging import root
# os.environ['ALUMINUM_SHARK_BACKEND_LOGGING'] = '1'

from unittest import result
import uuid
import warnings
import os
import ctypes
from typing import Union, List, Iterable
from inspect import currentframe, stack
 
# from aluminum_shark.python.aluminum_shark.core import Context

def AS_LOG(*args, hex_pointers=True, **kwargs):
  """
  Loggin function. Logs the filename and line it was called from. `args` and 
  `kwargs` are forwarded to `print`.
  """
  args = list(args)
  if hex_pointers:
    for i in range(len(args)):
      if isinstance(args[i], ctypes.c_void_p):
        args[i] = str(args[i]) + '; ' + str(hex(args[i].value))

  cf = currentframe()
  print("client:", f"{stack()[1][1]}:{cf.f_back.f_lineno}" + "]", *args,
        **kwargs)


path='/root/aluminum_shark/python/aluminum_shark/'

__DEFAULT_BACKEND__ = os.path.join(os.path.dirname(path),
                                   'aluminum_shark_seal.so')
AS_LOG('default backend: ', __DEFAULT_BACKEND__)


# get the client shared library path
# for now we can hardcode and figure out how to import dynamically later put comment line argument
client_dir = '/root/aluminum_shark/'
lib_client_path = os.path.join(client_dir, 'client', 'libclient.so')
if not os.path.exists(lib_client_path):
  raise Exception('Unable to find client shared library ' + lib_client_path)  

  
# load the library and functions
client_lib = ctypes.CDLL(lib_client_path)
AS_LOG("Wrapped Client library: " + lib_client_path)


############################
# backend functions        #
############################

# load and destroy backend
load_backend_func = client_lib.client_loadBackend
load_backend_func.argtypes = [ctypes.c_char_p]
load_backend_func.restype = ctypes.c_void_p

destroy_backend_func = client_lib.client_destroyBackend
destroy_backend_func.argtypes = [ctypes.c_void_p]

def loadBackend(clt_loadbackend):
    encoded_loadbackend=str.encode(clt_loadbackend)  #binary rep 
    arg_loadbackend=ctypes.c_char_p(encoded_loadbackend) #change var names to more descriptive names
    return load_backend_func(arg_loadbackend)

# create and destroy context
# ckks
create_backend_ckks_func = client_lib.client_CreateContextCKKS
create_backend_ckks_func.argtypes = [
    ctypes.c_size_t,  # poly_modulus_degree
    ctypes.POINTER(ctypes.c_int),  # a list containing the coeff_modulus
    ctypes.c_int,  # number of moduli in the coeff_modulus list
    ctypes.c_double,  # scale
    ctypes.c_void_p  # backend handle 
]
create_backend_ckks_func.restype = ctypes.c_void_p


#save the context
#ckks
# save_context_ckks_func = client_lib.client_SaveContext
# save_context_ckks_func.argtypes = [
#     ctypes.c_size_t,  # poly_modulus_degree
#     ctypes.POINTER(ctypes.c_int),  # a list containing the coeff_modulus
#     ctypes.c_int,  # number of moduli in the coeff_modulus list
#     ctypes.c_double,  # scale
#     ctypes.c_void_p  # backend handle 
# ]
#need to change all variables names 

############################
# context functions        #
############################

# key management
create_pub_key_func = client_lib.client_CreatePublicKey
create_pub_key_func.argtypes = [ctypes.c_void_p]

create_priv_key_func = client_lib.client_CreatePrivateKey
create_priv_key_func.argtypes = [ctypes.c_void_p]

save_pub_key_func = client_lib.client_SavePublicKey
save_pub_key_func.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

save_priv_key_func = client_lib.client_SavePrivateKey
save_priv_key_func.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

load_pub_key_func = client_lib.client_LoadPublicKey
load_pub_key_func.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

load_pri_key_func = client_lib.client_LoadPrivateKey
load_pri_key_func.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

# save_Context_func = client_lib.client_SaveContext
# save_Context_func.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

save_Context_gk_func = client_lib.client_SaveContextGK
save_Context_gk_func.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

save_Context_rk_func = client_lib.client_SaveContextRK
save_Context_rk_func.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

save_Context_encryption_parameters_func = client_lib.client_SaveEncrpytionParameters
save_Context_encryption_parameters_func.argtypes = [ctypes.c_char_p,ctypes.c_void_p]
 
# loading 

load_Context_func = client_lib.client_LoadContext
load_Context_func.argtypes = [ctypes.c_char_p,ctypes.c_double]

load_Context_gk_func = client_lib.client_LoadContextGK
load_Context_gk_func.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

load_Context_rk_func = client_lib.client_LoadContextRK
load_Context_rk_func.argtypes = [ctypes.c_char_p,ctypes.c_void_p]

load_Context_encryption_parameters_func = client_lib.client_LoadEncrpytionParameters
load_Context_encryption_parameters_func.argtypes = [ctypes.c_char_p,ctypes.c_void_p]


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

class Context(ObjectCleaner):

  context_map = {}
  
 
  @staticmethod
  def find_context(handle):
    return Context.context_map[handle]


  def __init__(self, handle: ctypes.c_void_p,backend: "HEBackend") -> None:
    super().__init__(parent=backend)
    self.__handle = handle
    self.__has_keys = False
    self.__has_pub_key = False
    self.__has_priv_key = False
    self.sav_pub_key=False
    self.sav_pri_key=False
    self.load_pub_key=False
    self.load_pri_key=False
    self.save_ctx=False
    self.save_ctx_gk=False
    self.save_ctx_rk=False
    self.save_ctx_encryption_parameters=False
    self.load_ctx_gk=False
    self.load_ctx_rk=False
    self.load_ctx_encryption_parameters=False
    self.load_ctx=False
    Context.context_map[handle] = self
    AS_LOG("Created Context", self)


  def create_keys(self) -> None:
    """
    Creates public and private key
    """
    self.create_public_key()
    self.create_private_key()
 
  def save_keys(self,path) -> None:
    """
    Creates public and private key
    """
    
    self.save_public_key(path+'.pk')
    self.save_private_key(path+'.sk')

  def load_keys(self,path) -> None:
    """
    Loads public and private key
    """
    
    self.load_public_key(path+'.pk')
    self.load_private_key(path+'.sk')  

  def save_context(self,path) -> None:
    """
    save context
    """
    # self.save_Context(path)
    self.save_context_gk(path+'.gk')
    self.save_context_rk(path+'.rk') 
    self.save_context_encryption_parameters(path+'.ep')

      

  def load_EPKeys(self,path) -> None:
    """
     context
    """

    self.load_context_gk(path+'.gk')
    self.load_context_rk(path+'.rk') 
    self.load_context_encryption_parameters(path+'.ep')


  def save_context_gk(self,path) -> None:
    path=str.encode(path)  
    """
    saves gk. 
    """

    # CKKS='data'
    AS_LOG(self.save_ctx_gk)     #
    
    if self.save_ctx_gk:
      return
    
    AS_LOG(self.__handle)          #
    save_Context_gk_func(ctypes.c_char_p(path),self.__handle)
    self.save_ctx_gk= True


  def save_context_rk(self,path) -> None:
    path=str.encode(path)  
    """
    saves rk. 
    """

    # CKKS='data'
    AS_LOG(self.save_ctx_rk)     #
    
    if self.save_ctx_rk:
      return
    
    AS_LOG(self.__handle)          #
    save_Context_rk_func(ctypes.c_char_p(path),self.__handle)
    self.save_ctx_rk= True

  def save_context_encryption_parameters(self,path) -> None:
    path=str.encode(path)  
    """
    saves encryption parameters
    """

    # CKKS='data'
    AS_LOG(self.save_ctx_encryption_parameters)     #
    
    if self.save_ctx_encryption_parameters:
      return
    
    AS_LOG(self.__handle)          #
    save_Context_encryption_parameters_func(ctypes.c_char_p(path),self.__handle)
    self.save_ctx_encryption_parameters= True  

  # def loadContext(self,path) -> None:
  #   path=str.encode(path)  
  #   """
  #   loads Context
  #   """
  #   AS_LOG(self.load_ctx)     #
    
  #   if self.load_ctx:
  #     return
    
  #   AS_LOG(self.__handle)          #
  #   load_Context_func(ctypes.c_char_p(path),self.__handle)
  #   self.load_ctx= True  



  def load_context_gk(self,path) -> None:
    path=str.encode(path)  
    """
    loads galoiskey
    """
    AS_LOG(self.load_ctx_gk)     #
    
    if self.load_ctx_gk:
      return
    
    AS_LOG(self.__handle)          #
    load_Context_gk_func(ctypes.c_char_p(path),self.__handle)
    self.load_ctx_gk= True

  def load_context_rk(self,path) -> None:
    path=str.encode(path)  
    """
    loads releinkey
    """
    AS_LOG(self.load_ctx_rk)     #
    
    if self.load_ctx_rk:
      return
    
    AS_LOG(self.__handle)          #
    load_Context_rk_func(ctypes.c_char_p(path),self.__handle)
    self.load_ctx_rk= True
    
  def load_context_encryption_parameters(self,path) -> None:
     path=str.encode(path)  
     """
     loads encryption parameters
    """
     AS_LOG(self.load_ctx_encryption_parameters)     #
    
     if self.load_ctx_encryption_parameters:
       return
    
     AS_LOG(self.__handle)          #
     save_Context_encryption_parameters_func(ctypes.c_char_p(path),self.__handle)
     self.load_ctx_encryption_parameters= True  

  def load_private_key(self,path) -> None:
    path=str.encode(path)  
    """
    loads a private key. 
    """
   

    AS_LOG(self.load_pri_key)     #
    
    if self.load_pri_key:
      return
    

    AS_LOG(self.__handle)          #
    load_pri_key_func(ctypes.c_char_p(path),self.__handle)
    self.load_pri_key = True


  def load_public_key(self,path) -> None:
    path=str.encode(path)  
    """
    loads a public key. 
    """

    AS_LOG(self.load_pub_key)     #
    
    if self.load_pub_key:
      return
    
    AS_LOG(self.__handle)          #
    load_pub_key_func(ctypes.c_char_p(path),self.__handle)
    self.load_pub_key = True


  def save_public_key(self,path) -> None:
    path=str.encode(path)  
    """
    Saves a public key. 
    """
    AS_LOG(self.sav_pub_key)    
    
    if self.sav_pub_key:
      return
    
    AS_LOG(self.__handle)          #
    save_pub_key_func(ctypes.c_char_p(path),self.__handle)
    self.sav_pub_key = True


  def save_private_key(self,path) -> None:
    path=str.encode(path)  
    """
    saves a priavte key. 
    """
   
    AS_LOG(self.sav_pri_key)     #
    
    if self.sav_pri_key:
      return
    

    AS_LOG(self.__handle)          #
    save_priv_key_func(ctypes.c_char_p(path),self.__handle)
    self.sav_pri_key = True

  def create_public_key(self) -> None:
    """
    Creates a public key. If a public key has already been created does nothing.
    """

    AS_LOG(self.__has_pub_key)     #

    if self.__has_pub_key:
      return
    
    AS_LOG(self.__handle)          #
    create_pub_key_func(self.__handle)
    self.__has_pub_key = True

  def create_private_key(self) -> None:
    """
    Creates a private key. If a private key has already been created does nothing.
    """
    AS_LOG(self.__has_priv_key)    #

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

  def createContextCKKS(self, poly_modulus_degree, coeff_modulus, scale):
    # convert coeff_modulus list
    coeff_modulus_ptr_t = ctypes.c_int * len(coeff_modulus)
    coeff_modulus_ptr = coeff_modulus_ptr_t(*coeff_modulus)

    AS_LOG('Creating context', create_backend_ckks_func,
           create_backend_ckks_func.argtypes, '->',
           create_backend_ckks_func.restype)

    handle = create_backend_ckks_func(poly_modulus_degree, coeff_modulus_ptr,
                                      len(coeff_modulus), scale, self.__handle)
                     
    return Context(handle,self)

  def loadContext(self,path,scale):


    load_hanlde=load_Context_func(self.__handle,path,scale)

    return Context(load_hanlde,self)


if __name__=='__main__':
  backend = HEBackend() 
  context = backend.createContextCKKS(8192, [60, 40, 40, 60], 50) 
  path='/root/aluminum_shark/client/data'
  context.create_keys()
  context.save_keys(path)
  context.save_context(path)
  # load the context
  load_con = backend.loadContext(path+'.ck',50)
  load_con.load_keys(path)
  load_con.load_EPKeys(path)
  

  
  
