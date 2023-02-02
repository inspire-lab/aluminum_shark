import os

# need to make sure this is set
os.environ['TF_XLA_FLAGS'] = '--tf_xla_enable_xla_devices'