import os
# enable XLA
os.environ['TF_XLA_FLAGS'] = '--tf_xla_enable_xla_devices'
import tensorflow as tf
import aluminum_shark.core as shark
import numpy as np

# create a dummy input
x_in = np.arange(50).reshape(10, 5) / 50

# create a function that returns a model
# we set the weights to be deterministic so we can compare the results
def create_model():
  model = tf.keras.Sequential()
  model.add(
      tf.keras.layers.Dense(3, activation=tf.square,
                            input_shape=x_in.shape[1:]))

  w, b = model.layers[0].get_weights()
  model.layers[0].set_weights([
      np.arange(w.size).reshape(w.shape) / w.size,
      np.arange(b.size).reshape(b.shape) / b.size
  ])
  print(np.arange(w.size).reshape(w.shape) / w.size)
  print(np.arange(b.size).reshape(b.shape) / b.size)

  return model

# get the correct output on plain data
y_true = create_model()(x_in)

# set it all up
print('loading backend')
# first we load the backend, in this case we use the openfhe backend
backend = shark.HEBackend(shark.OPENFHE_BACKEND)
print('backend loaded')

print('creating context')
# seal code
# context = backend.createContextCKKS(8192, [60, 40, 40, 60], 40)
# openfhe code
# next we create a context, in this case we use the CKKS scheme, with multiplicative depth 3
context = backend.createContext(scheme='ckks',
                                multiplicative_depth=3,
                                scaling_mod_size=50)
# create the keys
context.create_keys()
# encrypt the input
ctxt = context.encrypt(x_in, name='x', dtype=float, layout='batch')

# run computation using batch layout
enc_model = shark.EncryptedExecution(model_fn=create_model,
                                     context=context,
                                     forced_layout='batch')
result_ctxt = enc_model(ctxt, debug_inputs=[x_in])

# decrypt
decrypted = context.decrypt_double(result_ctxt[0])
# print('decrypted values \n', decrypted)
# print('actual values', y_true)
decrypted = np.array(decrypted)
if np.all(abs(decrypted - y_true) < 0.001):
  print("decryption with in rounding tolerance")
else:
  raise Exception('decryption does not match plaintext execution')

# clean up
backend.destroy()
