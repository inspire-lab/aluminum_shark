import os
from requests import get
# os.environ['TF_CPP_MIN_LOG_LEVEL'] = '0'
# os.environ['TF_CPP_MAX_VLOG_LEVEL'] = '1'
# os.environ['ALUMINUM_SHARK_LOGGING'] = '1'
os.environ['TF_XLA_FLAGS'] = '--tf_xla_enable_xla_devices'
# # os.environ['TF_XLA_FLAGS'] += ' --tf_mlir_enable_mlir_bridge'
# os.environ['TF_DUMP_GRAPH_PREFIX'] = \
#      '/home/robert/workspace/aluminum_shark/messing_around/graph_dump'
import tensorflow as tf
import aluminum_shark.core as shark
import numpy as np

print('TF version', tf.__version__)

shark.enable_logging(False)


def get_function():

  def f(x):
    y = tf.convert_to_tensor(np.arange(15).reshape((5, 3)), dtype=x.dtype)
    return tf.tensordot(x, y, axes=1)

  return f


# input values
x_in = np.arange(50).reshape(10, 5)
# set it all up
backend = shark.HEBackend(
    '/home/robert/workspace/aluminum_shark/seal_backend/aluminum_shark_seal.so')

context = backend.createContextCKKS(8192, [60, 40, 40, 60], 50)
context.create_keys()
print('availabel layouts:', backend.layouts)

# for layout in backend.layouts:
for layout in ['simple']:
  print(
      '########################################################################'
  )
  print(f'running with {layout} layout')
  ctxt = context.encrypt(x_in, name='x', dtype=float, layout=layout)

  # run computation
  enc_model = shark.EncryptedExecution(model_fn=get_function, context=context)
  result_ctxt = enc_model(ctxt, debug_inputs=[x_in])

  y_true = get_function()(x_in).numpy()
  print("true results:", y_true)
  print('ctxt shape:', result_ctxt[0].shape)

  # decrypt
  print('decrypting:')
  decrypted = context.decrypt_double(result_ctxt[0])
  print('decrypted values\n', decrypted)
  print('actual values\n', y_true)
  if np.all(np.abs(decrypted - y_true) < 0.001):
    print("decryption with in rounding tolerance")
  else:
    raise Exception('decryption does not match plaintext execution')

# clean up
backend.destroy()

print(
    '\n###############################\n\tSUCCESS\n###############################'
)
