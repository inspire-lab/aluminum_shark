import os

os.environ['ALUMINUM_SHARK_LOGGING'] = '1'
os.environ['ALUMINUM_SHARK_BACKEND_LOGGING'] = '1'

from aluminum_shark import config

# load minmal debug py_handle.so
config.PY_HANDLE_SHARED_LIB = os.path.join(os.getcwd(), 'py_handle_test.so')
import aluminum_shark.core as shark
import numpy as np

x_in = np.arange(50).reshape(10, 5) / 50

# set it all up
backend = shark.HEBackend()

context = backend.createContextCKKS(8192, [60, 40, 40, 60], 40)
context.create_keys()
ctxt = context.encrypt(x_in, name='x', dtype=float, layout='batch')

backend.destroy()
