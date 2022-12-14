SRC_DIR := .
OBJ_DIR := obj
SRC_FILES := $(wildcard $(SRC_DIR)/*.cc)
OBJ_FILES := $(patsubst $(SRC_DIR)/%.cc,$(OBJ_DIR)/%.o,$(SRC_FILES))
LDFLAGS := -shared -std=c++17
# CPPFLAGS := ...
CXXFLAGS := -O0 -g3 -Wall -shared -std=c++17 -fPIC
INCLUDES := -I../dependencies/SEAL/bin/include/SEAL-3.7/ -I../dependencies/tensorflow/tensorflow/compiler/plugin/aluminum_shark -I../dependencies/tensorflow
LIBS := ../dependencies/SEAL/bin/lib/libseal-3.7.a


libclient.so: $(OBJ_FILES) $(OBJ_DIR)/logging.o $(OBJ_DIR)/he_backend.o
	@echo linking $(OBJ_FILES)
	c++ $(LDFLAGS) -o $@ $^ $(LIBS) 

	
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cc
	@echo compiling $^
	c++ $(CPPFLAGS) $(CXXFLAGS) $(INCLUDES) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/he_backend.o: ../dependencies/tensorflow/tensorflow/compiler/plugin/aluminum_shark/he_backend/he_backend.cc
	@echo compiling $^
	c++ $(CPPFLAGS) $(CXXFLAGS) $(INCLUDES) $(CFLAGS) -c -o $@ $<

$(OBJ_DIR)/logging.o: ../dependencies/tensorflow/tensorflow/compiler/plugin/aluminum_shark/logging.cc
	@echo compiling $^
	c++ $(CPPFLAGS) $(CXXFLAGS) $(INCLUDES) $(CFLAGS) -c -o $@ $<

.PHONY : clean

clean:
	rm -f $(OBJ_DIR)/*.o libclient.so 


 