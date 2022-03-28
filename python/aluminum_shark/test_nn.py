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

x_in = np.arange(50).reshape(10, 5)
print(x_in)


def create_model():
  model = tf.keras.Sequential()
  model.add(
      tf.keras.layers.Dense(
          3,
          #  activation=tf.square,
          input_shape=x_in.shape[1:]))

  w, b = model.layers[0].get_weights()
  model.layers[0].set_weights(
      [np.arange(w.size).reshape(w.shape),
       np.arange(b.size).reshape(b.shape)])
  return model


y_true = create_model()(x_in)
print(y_true)

# @tf.function(jit_compile=True)
# def f(x):
#   # return tf.square(x) + [5, 6, 7, 8]
#   return tf.square(x) + [[5, 6], [7, 8]]

# # input values
# # x_in = np.array([1, 2, 3, 4])
# x_in = np.array([[1, 2], [3, 4]])

# set it all up
backend = shark.HEBackend(
    '/home/robert/workspace/aluminum_shark/seal_backend/aluminum_shark_seal.so')

context = backend.createContextCKKS(8192, [60, 40, 40, 60], 40)
context.create_keys()
ctxt = context.encrypt(x_in, name='x', dtype=float)

# run computation
enc_model = shark.EncryptedExecution(model_fn=create_model, context=context)
result_ctxt = enc_model(ctxt)

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
