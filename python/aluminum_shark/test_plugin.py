import os
# os.environ['TF_CPP_MIN_LOG_LEVEL'] = '0'
# os.environ['TF_CPP_MAX_VLOG_LEVEL'] = '1'
os.environ['ALUMINUM_SHARK_LOGGING'] = '1'
os.environ['TF_XLA_FLAGS'] = '--tf_xla_enable_xla_devices'
# os.environ['TF_XLA_FLAGS'] += ' --tf_mlir_enable_mlir_bridge'
os.environ['TF_DUMP_GRAPH_PREFIX'] = \
     '/home/robert/workspace/aluminum_shark/messing_around/graph_dump'
import tensorflow as tf
import aluminum_shark.core as shark
import numpy as np

print('TF version', tf.__version__)


def get_function():

  def f(x):
    # return tf.square(x) + [5, 6, 7, 8]
    return tf.square(x) + [[5, 6], [7, 8]]

  return f


# input values
# x_in = np.array([1, 2, 3, 4])
x_in = np.array([[1, 2], [3, 4]])

# set it all up
backend = shark.HEBackend(
    '/home/robert/workspace/aluminum_shark/seal_backend/aluminum_shark_seal.so')

context = backend.createContextCKKS(8192, [60, 40, 40, 60], 40)
context.create_keys()
ctxt = context.encrypt(x_in, name='x', dtype=float)

# run computation
enc_model = shark.EncryptedExecution(model_fn=get_function, context=context)
result_ctxt = enc_model(ctxt)

y_true = get_function()(x_in).numpy()
print("on AS", y_true)

# decrypt
decrypted = context.decrypt_double(result_ctxt[0])[:4]
print('decrypted values', decrypted)
print('actual values', y_true)
decrypted = np.array(decrypted)
if all((decrypted - y_true) < 0.001):
  print("decryption with in rounding tolerance")
else:
  raise Exception('decryption does not match plaintext execution')

# clean up
backend.destroy()
