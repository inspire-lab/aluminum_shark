from setuptools import setup
from setuptools import find_packages

with open("README.md", "r") as fh:
  long_description = fh.read()

# TODO: dependency handling
setup(
    name='aluminum_shark',
    version='0.0.1',
    description=
    'Privacy Preserving Neural Networks with TensorFlow und Homomorphic Encryption',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Robert Podschwadt',
    author_email='robertpodschwadt@gmail.com',
    url='https://github.com/podschwadt/aluminum_shark',
    package_dir={"": "python"},
    packages=find_packages(where="python"),
    #     include_package_data=True,
    #     package_data={
    #         'seal_backend': ['aluminum_shark_seal.so'],
    #     },
    data_files=[
        ('', ['seal_backend/aluminum_shark_seal.so']),
    ])
