include Makefile.vars
# if you run into an error that states it can't find Makefiel.vars, you need to
# run `create_makefile_vars.py` first

# Compiler
CXX = g++

# Compiler flags
CXXFLAGS = -Wall -Wextra -std=c++14 -Wno-unused-variable -Wno-unused-parameter 

# Source files
SRCS = plugin.cc

# Object files
OBJS = $(SRCS:.cc=.o)

# Target shared library
TARGET = shark_tf_plugin.so

# Default target
all: $(TARGET)

# Rule to compile object files (currently not used since there is only one file)
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Rule to link the shared library
# $(TARGET): $(OBJS) this becomes interessting when there is more than one file
$(TARGET):
	@echo "compiling and linking plugin. using tensorflow include dir $(TF_INC_DIR) and linking against $(TF_LIB_DIR)/$(TF_LIB_FILE)} "
	$(CXX) $(CXXFLAGS) -shared plugin.cc -o $@ -fPIC -I$(TF_INC_DIR) -L$(TF_LIB_DIR) -l:$(TF_LIB_FILE)

.PHONY: clean 
# Clean rule
clean:
	rm -f $(OBJS) $(TARGET)

# install the flie by sym-linking it to the tensorflow plugin dir
install:
	mkdir -p $(TF_LIB_DIR)/tensorflow-plugins 
	ln -s `readlink -f $(TARGET)` $(TF_LIB_DIR)/tensorflow-plugins/

 


