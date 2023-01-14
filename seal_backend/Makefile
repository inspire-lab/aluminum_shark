SRC_DIR := .
OBJ_DIR := obj
COM_DIR := ../common
COM_FILES := $(shell ls ../common/*.cc) 
SRC_FILES := $(wildcard $(SRC_DIR)/*.cc)
OBJ_FILES := $(patsubst $(SRC_DIR)/%.cc,$(OBJ_DIR)/%.o,$(SRC_FILES))
SRC_FILES += $(COM_FILES)
OBJ_FILES += $(patsubst $(COM_DIR)/%.cc,$(OBJ_DIR)/%.o,$(COM_FILES))
LDFLAGS := -shared -std=c++17
# CPPFLAGS := ...
CXXFLAGS := -O0 -g3 -Wall -shared -std=c++17 -fPIC
INCLUDES := -I../dependencies/SEAL/bin/include/SEAL-3.7/ 
INCLUDES += -I../dependencies/tensorflow/tensorflow/compiler/plugin/aluminum_shark 
INCLUDES += -I../dependencies/tensorflow/
INCLUDES += -I$(COM_DIR)
LIBS := ../dependencies/SEAL/bin/lib/libseal-3.7.a


aluminum_shark_seal.so: $(OBJ_FILES)  $(OBJ_DIR)/logging.o $(OBJ_DIR)/utils.o $(OBJ_DIR)/arg_utils.o
	@echo linking $(OBJ_FILES)
	c++ $(LDFLAGS) -o $@ $^ $(LIBS)


$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cc 
	@echo compiling $^
	c++ $(CPPFLAGS) $(CXXFLAGS) $(INCLUDES) $(CFLAGS) -c -o $@ $<


$(OBJ_DIR)/%.o: $(COM_DIR)/%.cc 
	@echo compiling $^
	c++ $(CPPFLAGS) $(CXXFLAGS) $(INCLUDES) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/logging.o:
	@echo compiling logging
	c++ $(CPPFLAGS) $(CXXFLAGS) $(INCLUDES) $(CFLAGS) -c -o $@ ../dependencies/tensorflow/tensorflow/compiler/plugin/aluminum_shark/logging.cc

$(OBJ_DIR)/utils.o:
	@echo compiling logging
	c++ $(CPPFLAGS) $(CXXFLAGS) $(INCLUDES) $(CFLAGS) -c -o $@ ../dependencies/tensorflow/tensorflow/compiler/plugin/aluminum_shark/utils/utils.cc

$(OBJ_DIR)/arg_utils.o:
	@echo compiling logging
	c++ $(CPPFLAGS) $(CXXFLAGS) $(INCLUDES) $(CFLAGS) -c -o $@ ../dependencies/tensorflow/tensorflow/compiler/plugin/aluminum_shark/python/arg_utils.cc


.PHONY : clean test

test: 
	@echo $(SRC_FILES)
	@echo $(OBJ_FILES)

clean:
	rm -f $(OBJ_DIR)/*.o  aluminum_shark_seal.so 

install:
	ln -s  ../../seal_backend/aluminum_shark_seal.so ../python/aluminum_shark/aluminum_shark_seal.so