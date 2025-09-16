# Compiler and flags
CXX = g++
CXXFLAGS = -std=c++17 -Wall -pthread

# Source files
SRCS = ui.cpp scan.cpp attack.cpp attack1.cpp


# Object files (derived from source files)
OBJS = $(SRCS:.cpp=.o)

# Target executable name
TARGET = netcut

# Default rule: build the executable
all: $(TARGET)

# Rule to link the object files into the final executable
$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(OBJS)

# Generic rule to compile .cpp files into .o object files
%.o: %.cpp common.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Rule to clean up build files
clean:
	rm -f $(OBJS) $(TARGET)

# Phony targets
.PHONY: all clean