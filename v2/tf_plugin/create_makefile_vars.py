import tensorflow as tf
import os

# Discover TensorFlow include directory
tf_include_dir = tf.sysconfig.get_include()
tf_lib_dir = os.path.join(tf.sysconfig.get_lib(), 'python')

# Set the include directory in the build script
build_script = f"""
TF_INC_DIR={tf_include_dir}
TF_LIB_DIR={tf_lib_dir}
"""
for f in os.listdir(tf_lib_dir):
  if f.startswith("_pywrap_tensorflow_internal"):
    build_script += f"TF_LIB_FILE={f}\n"
    break

# Write the build script to a file
build_script_file = "Makefile.vars"
with open(build_script_file, "w") as file:
  file.write(build_script)

print("Build script created at:", build_script_file)
