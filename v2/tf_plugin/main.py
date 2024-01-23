import os
# os.environ['TF_CPP_MIN_LOG_LEVEL'] = '0'
# os.environ['TF_CPP_MAX_VLOG_LEVEL'] = '1'
os.environ['TF_PLUGGABLE_DEVICE_LIBRARY_PATH'] = "."
import tensorflow as tf


# check if our device is registered
success = False
devices = tf.config.list_physical_devices()
for dev in devices:
  if dev.device_type == "HE":
    success = True
    break
assert success, "HE device not registered"

print('successfully loaded HE device' , dev)

# this breaks things atm. most likely because the stream executor doesnt do 
# anyhting. especially no memory allocation
# with tf.device('HE:0'):
#   tf.constant([1,2,3])