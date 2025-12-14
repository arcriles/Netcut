# Compiler
CXX = g++

# Flags: Standard C++17, Warnings, Thread support, Position Independent Code
# We use pkg-config to get the correct Include paths for Qt5
CXXFLAGS = -std=c++17 -Wall -pthread -fPIC $(shell pkg-config --cflags Qt5Widgets)

# Linker Flags: Get libraries for Qt5 Widgets
LDFLAGS = $(shell pkg-config --libs Qt5Widgets)

# Source files (Excluding the old ui.cpp)
SRCS = scan.cpp attack.cpp attack1.cpp gui_main.cpp

# Object files
OBJS = $(SRCS:.cpp=.o)

# Target executable
TARGET = netcut-gui

# Default rule
all: $(TARGET)

# Link
$(TARGET): $(OBJS)
	$(CXX) $(OBJS) -o $(TARGET) $(LDFLAGS)

# Compile C++ source to object files
# Note: gui_main.cpp depends on gui_main.moc
%.o: %.cpp common.hpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Generate Meta-Object Code for Qt
gui_main.moc: gui_main.cpp
	moc gui_main.cpp -o gui_main.moc

# Explicit dependency for gui_main.o to ensure moc is generated first
gui_main.o: gui_main.moc

clean:
	rm -f $(OBJS) $(TARGET) gui_main.moc

.PHONY: all clean