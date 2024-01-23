TF_PLUGIN_DIR = ../../dependencies/tensorflow/tensorflow/compiler/plugin/aluminum_shark/
# VPATH = $(TF_PLUGIN_DIR):$(TF_PLUGIN_DIR)/python:$(TF_PLUGIN_DIR)/he_backend
# most of these are disabled due to dependency issues
CC_FILES := ctxt.cc ptxt.cc base_txt.cc layout.cc logging.cc python/python_handle.cc he_backend/he_backend.cc
# CC_FILES := he_backend/he_backend.cc logging.cc
SRC_FILES := $(addprefix $(TF_PLUGIN_DIR)/,$(CC_FILES))
# $(info $$SRC_FILES is [${SRC_FILES}])
OBJ_DIR := obj
OBJ_FILES := $(addprefix $(OBJ_DIR)/,$(addsuffix .o,$(basename $(notdir $(CC_FILES)))))
$(info $$OBJ_FILES is [${OBJ_FILES}])

LDFLAGS := -shared -std=c++17
# CPPFLAGS := ...
CPPFLAGS := -O0 -g3 -Wall --std=c++17 -fPIC -Wno-unused-local-typedefs -DALUMINUM_SHARK_MINIMAL_LAYOUT=1
INCLUDES := -I../../dependencies/tensorflow/tensorflow/compiler/plugin/aluminum_shark -I../../dependencies/tensorflow/ -I../../dependencies/SEAL/bin/include/SEAL-3.7/ 
LIBS := ../../dependencies/SEAL/bin/lib/libseal-3.7.a 

all: seal_test rotate_test py_handle_test py_handle_test.so substract_test #is broken

seal_test:
	@echo compiling $@
	c++  $(CPPFLAGS) $(INCLUDES) -o $@ $@.cc $(LIBS)

size_test:
	@echo compiling $@
	c++  $(CPPFLAGS) $(INCLUDES) -o $@ $@.cc $(LIBS)

py_handle_test: $(OBJ_FILES) $(OBJ_DIR)/py_handle_test.o
	@echo linking $@
	c++ --std=c++17 -O0 -g3 $^ -ldl -o $@

rotate_test: $(OBJ_FILES) $(OBJ_DIR)/rotate_test.o
	@echo linking $@
	c++ --std=c++17 -O0 -g3 $^ -ldl -o $@

substract_test: $(OBJ_FILES) $(OBJ_DIR)/substract_test.o
	@echo linking $@
	c++ --std=c++17 -O0 -g3 $^ -ldl -o $@

py_handle_test.so: $(OBJ_FILES)
	@echo linking py_handle_test.so
	c++ -shared $^ -o py_handle_test.so

$(OBJ_DIR)/py_handle_test.o:
	@echo compiling py_handle_test.cc
	c++ $(CPPFLAGS) $(INCLUDES) -c -o $@ py_handle_test.cc

$(OBJ_DIR)/rotate_test.o:
	@echo compiling rotate_test.cc
	c++ $(CPPFLAGS) $(INCLUDES) -c -o $@ rotate_test.cc

$(OBJ_DIR)/substract_test.o:
	@echo compiling substract_test.cc
	c++ $(CPPFLAGS) $(INCLUDES) -c -o $@ substract_test.cc

$(OBJ_DIR)/ctxt.o:
	@echo compiling $(TF_PLUGIN_DIR)/ctxt.cc
	c++ $(CPPFLAGS)  $(INCLUDES) -c -o $@ $(TF_PLUGIN_DIR)/ctxt.cc

$(OBJ_DIR)/ptxt.o:
	@echo compiling $(TF_PLUGIN_DIR)/ptxt.cc
	c++ $(CPPFLAGS) $(INCLUDES) -c -o $@ $(TF_PLUGIN_DIR)/ptxt.cc

$(OBJ_DIR)/base_txt.o:
	@echo compiling $(TF_PLUGIN_DIR)/base_txt.cc
	c++ $(CPPFLAGS)  $(INCLUDES) -c -o $@ $(TF_PLUGIN_DIR)/base_txt.cc

$(OBJ_DIR)/python_handle.o:
	@echo compiling $(TF_PLUGIN_DIR)/python/python_handle.cc
	c++ $(CPPFLAGS)  $(INCLUDES) -c -o $@ $(TF_PLUGIN_DIR)/python/python_handle.cc

$(OBJ_DIR)/logging.o:
	@echo compiling $(TF_PLUGIN_DIR)/logging.cc
	c++ $(CPPFLAGS)  $(INCLUDES) -c -o $@ $(TF_PLUGIN_DIR)/logging.cc

$(OBJ_DIR)/layout.o:
	@echo compiling $(TF_PLUGIN_DIR)/layout.cc
	c++ $(CPPFLAGS)  $(INCLUDES) -c -o $@ $(TF_PLUGIN_DIR)/layout.cc

$(OBJ_DIR)/he_backend.o:
	@echo compiling $(TF_PLUGIN_DIR)he_backend/he_backend.cc
	c++ $(CPPFLAGS) $(INCLUDES) -c -o $@ $(TF_PLUGIN_DIR)/he_backend/he_backend.cc


.PHONY : clean

make clean:
	rm -f $(OBJ_DIR)/*.o  aluminum_shark_seal_test.so py_handle_test substract_test seal_test rotate_test