import os
# os.environ['TF_CPP_MIN_LOG_LEVEL'] = '0'
# os.environ['TF_CPP_MAX_VLOG_LEVEL'] = '1'
os.environ['ALUMINUM_SHARK_LOGGING'] = '1'
os.environ['ALUMINUM_SHARK_BACKEND_LOGGING'] = '1'
os.environ['TF_XLA_FLAGS'] = '--tf_xla_enable_xla_devices'

import tensorflow as tf
import aluminum_shark.core as shark
import numpy as np

print('TF version', tf.__version__)

shark.set_log_level(0)

n_items = 5 * 5
x_in = np.arange(n_items, dtype=float).reshape(5, 5)
print(x_in)


def create_model():

  def model(x):
    return tf.matmul(x, x_in)

  return model


y_true = create_model()(x_in)
print(y_true)

# set it all up
backend = shark.HEBackend()

context = backend.createContextCKKS(8192, [60, 30, 30, 30, 60], 30)
context.create_keys()
ctxt = context.encrypt(x_in, name='x', dtype=float, layout='e2dm')

print(backend.layouts)

# run computation
enc_model = shark.EncryptedExecution(model_fn=create_model, context=context)
result_ctxt = enc_model(ctxt, debug_inputs=[x_in])

# decrypt
decrypted = context.decrypt_double(result_ctxt[0])
decrypted = np.array(decrypted)
if np.all(abs(decrypted - y_true) < 0.001):
  print("decryption with in rounding tolerance")
else:
  print('decrypted values \n', decrypted)
  print('actual values', y_true)
  raise Exception('decryption does not match plaintext execution')

# clean up
backend.destroy()
