#!/bin/bash

# checks out the required depncies in the correct versions
source <(grep = VERSIONS)
echo SEAL_VERSION ${SEAL_VERSION}
if [ -d "dependencies/SEAL" ] 
then
  git -C dependencies/SEAL fetch
  git -C dependencies/SEAL switch ${SEAL_VERSION}
else
  git clone --depth 1 --branch ${SEAL_VERSION} git@github.com:microsoft/SEAL.git dependencies/SEAL
fi
echo ALUMINUM_SHARK_TF_VERSION ${ALUMINUM_SHARK_TF_VERSION}
if [ -d "dependencies/tensorflow" ] 
then
  git -C fetch dependencies/tensorflow
  git -C dependencies/tensorflow switch ${ALUMINUM_SHARK_TF_VERSION}
else
  git clone --depth 1 --branch ${ALUMINUM_SHARK_TF_VERSION} git@github.com:podschwadt/aluminum_shark_tf.git dependencies/tensorflow
fi

