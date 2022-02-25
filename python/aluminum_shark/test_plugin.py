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


@tf.function(jit_compile=True)
def f(x):
  # return tf.square(x) + [5, 6, 7, 8]
  return tf.square(x) + [[5, 6], [7, 8]]


# input values
# x_in = np.array([1, 2, 3, 4])
x_in = np.array([[1, 2], [3, 4]])

# set it all up
backend = shark.HEBackend(
    '/home/robert/workspace/aluminum_shark/seal_backend/aluminum_shark_seal.so')

context = backend.createContextCKKS(8192, [60, 40, 40, 60], 40)
context.create_keys()
ctxt = context.encrypt(x_in.reshape(-1), name='x', dtype=float)
shark.set_ciphertexts(ctxt)

x = tf.convert_to_tensor(x_in)

# run computation
with tf.device("/device:XLA_HE:0"):
  y_true = f(x).numpy()
  print("on AS", y_true)

# retrieve result
result_ctxt = shark.get_ciphertexts()

# decrypt
decrypted = context.decrypt_double(result_ctxt)[:4]
print('decrypted values', decrypted)
print('actual values', y_true)
decrypted = np.array(decrypted)
if all((decrypted - y_true) < 0.001):
  print("decryption with in rounding tolerance")
else:
  raise Exception('decryption does not match plaintext execution')

# clean up
backend.destroy()
