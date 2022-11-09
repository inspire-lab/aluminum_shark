import os

os.environ['TF_XLA_FLAGS'] = '--tf_xla_enable_xla_devices'
os.environ['ALUMINUM_SHARK_LOGGING'] = '1'
import tensorflow as tf
import aluminum_shark.core as shark
import numpy as np

shark.set_log_level(10)

x_in = tf.keras.datasets.mnist.load_data()

# [60000, 784] Mnist

# [4096, 784] Plain batch

# [784] ctxts
# w0 = .5
# w0.shape = [4096,1]
# x0.shape = [4096,1]

# x0 *w0 + x1 *w1 + ... xn * wn

# # different encoding
# [1,784]
# x = [1] ctxt
# w = [1] weight vector

# x*w = [ x0 *w0 , x1 *w1,.., xn*wn]

x = np.random.rand(4, 5)

print(x)

x[x < 0.9] = 0
print(x)