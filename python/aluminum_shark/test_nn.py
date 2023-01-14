import os
# os.environ['TF_CPP_MIN_LOG_LEVEL'] = '0'
# os.environ['TF_CPP_MAX_VLOG_LEVEL'] = '1'
os.environ['ALUMINUM_SHARK_LOGGING'] = '1'
os.environ['ALUMINUM_SHARK_BACKEND_LOGGING'] = '1'
os.environ['TF_XLA_FLAGS'] = '--tf_xla_enable_xla_devices'
# os.environ['TF_XLA_FLAGS'] += ' --tf_mlir_enable_mlir_bridge'
# os.environ['TF_DUMP_GRAPH_PREFIX'] = \
#      '/home/robert/workspace/aluminum_shark/messing_around/graph_dump'
import tensorflow as tf
import aluminum_shark.core as shark
import numpy as np

print('TF version', tf.__version__)

x_in = np.arange(50).reshape(10, 5) / 50
print(x_in)
shark.set_log_level(0)


def create_model():
  model = tf.keras.Sequential()
  model.add(
      tf.keras.layers.Dense(3, activation=tf.square,
                            input_shape=x_in.shape[1:]))
  # model.add(tf.keras.layers.BatchNormalization())

  w, b = model.layers[0].get_weights()
  # # print(w.shape)
  model.layers[0].set_weights([
      np.arange(w.size).reshape(w.shape) / w.size,
      np.arange(b.size).reshape(b.shape) / b.size
  ])
  print(np.arange(w.size).reshape(w.shape) / w.size)
  print(np.arange(b.size).reshape(b.shape) / b.size)
  return model


y_true = create_model()(x_in)
# print(y_true)

# set it all up
print('loading backend')
backend = shark.HEBackend(
    '/home/robert/workspace/aluminum_shark/python/aluminum_shark/aluminum_shark_openfhe.so'
)
print('backend loaded')

print('creating context')
# seal code
# context = backend.createContextCKKS(8192, [60, 40, 40, 60], 40)
context = backend.createContext(scheme='ckks',
                                multiplicative_depth=3,
                                scaling_mod_size=50)
context.create_keys()
ctxt = context.encrypt(x_in, name='x', dtype=float, layout='batch')

# run computation
enc_model = shark.EncryptedExecution(model_fn=create_model,
                                     context=context,
                                     forced_layout='batch')
result_ctxt = enc_model(ctxt, debug_inputs=[x_in])

# decrypt
decrypted = context.decrypt_double(result_ctxt[0])
print('decrypted values \n', decrypted)
print('actual values', y_true)
decrypted = np.array(decrypted)
if np.all(abs(decrypted - y_true) < 0.001):
  print("decryption with in rounding tolerance")
else:
  raise Exception('decryption does not match plaintext execution')

# clean up
backend.destroy()
