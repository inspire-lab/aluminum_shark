SO_FILE := aluminum_shark_openfhe.so
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
CXXFLAGS := -O0 -g3 -Wall -shared -std=c++17 -fPIC -DMATHBACKEND=4 -fopenmp
# Include paths
INCLUDES := -I../dependencies/openfhe-development/bin/include/openfhe/pke 
INCLUDES += -I../dependencies/openfhe-development/bin/include/openfhe/core 
INCLUDES += -I../dependencies/openfhe-development/bin/include/openfhe
INCLUDES += -I../dependencies/tensorflow/tensorflow/compiler/plugin/aluminum_shark
INCLUDES += -I../dependencies/tensorflow/
INCLUDES += -I$(COM_DIR)
# libraries
LIBS := ../dependencies/openfhe-development/bin/lib/libOPENFHEbinfhe_static.a 
LIBS += ../dependencies/openfhe-development/bin/lib/libOPENFHEpke_static.a
LIBS += ../dependencies/openfhe-development/bin/lib/libOPENFHEcore_static.a
LIBS += -lgomp

$(SO_FILE): $(OBJ_FILES) $(OBJ_DIR)/logging.o $(OBJ_DIR)/utils.o $(OBJ_DIR)/arg_utils.o
	@echo linking $(OBJ_FILES)
	c++ $(LDFLAGS) -o $@ $^ $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cc
	@echo compiling $^
	c++ $(CPPFLAGS) $(CXXFLAGS)  $(INCLUDES) $(CFLAGS) -c -o $@ $<


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


.PHONY : clean

clean:
	rm -f $(OBJ_DIR)/*.o  $(SO_FILE) 

install:
	ln -s  ../../openfhe_backend/$(SO_FILE) ../python/aluminum_shark/$(SO_FILE)