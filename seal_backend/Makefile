SRC_DIR := .
OBJ_DIR := obj
SRC_FILES := $(wildcard $(SRC_DIR)/*.cc)
OBJ_FILES := $(patsubst $(SRC_DIR)/%.cc,$(OBJ_DIR)/%.o,$(SRC_FILES))
LDFLAGS := -shared -std=c++17
# CPPFLAGS := ...
CXXFLAGS := -O0 -g3 -Wall -shared -std=c++17 -fPIC
INCLUDES := -I../dependencies/SEAL/bin/include/SEAL-3.7/ -I../dependencies/tensorflow/tensorflow/compiler/plugin/aluminum_shark 
LIBS := ../dependencies/SEAL/bin/lib/libseal-3.7.a

aluminum_shark_seal.so: $(OBJ_FILES)
	@echo linking $(OBJ_FILES)
	c++ $(LDFLAGS) -o $@ $^ $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cc
	@echo compiling $^
	c++ $(CPPFLAGS) $(CXXFLAGS) $(INCLUDES) -c -o $@ $<


.PHONY : clean

clean:
	rm -f $(OBJ_DIR)/*.o  aluminum_shark_seal.so 

install:
	ln -s  ../../seal_backend/aluminum_shark_seal.so ../python/aluminum_shark/aluminum_shark_seal.so