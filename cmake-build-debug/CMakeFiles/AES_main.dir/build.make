# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.14

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /snap/clion/73/bin/cmake/linux/bin/cmake

# The command to remove a file.
RM = /snap/clion/73/bin/cmake/linux/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/frank/CLionProjects/AES_main

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/frank/CLionProjects/AES_main/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/AES_main.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/AES_main.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/AES_main.dir/flags.make

CMakeFiles/AES_main.dir/main.cpp.o: CMakeFiles/AES_main.dir/flags.make
CMakeFiles/AES_main.dir/main.cpp.o: ../main.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/frank/CLionProjects/AES_main/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/AES_main.dir/main.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/AES_main.dir/main.cpp.o -c /home/frank/CLionProjects/AES_main/main.cpp

CMakeFiles/AES_main.dir/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/AES_main.dir/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/frank/CLionProjects/AES_main/main.cpp > CMakeFiles/AES_main.dir/main.cpp.i

CMakeFiles/AES_main.dir/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/AES_main.dir/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/frank/CLionProjects/AES_main/main.cpp -o CMakeFiles/AES_main.dir/main.cpp.s

CMakeFiles/AES_main.dir/util.cpp.o: CMakeFiles/AES_main.dir/flags.make
CMakeFiles/AES_main.dir/util.cpp.o: ../util.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/frank/CLionProjects/AES_main/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/AES_main.dir/util.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/AES_main.dir/util.cpp.o -c /home/frank/CLionProjects/AES_main/util.cpp

CMakeFiles/AES_main.dir/util.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/AES_main.dir/util.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/frank/CLionProjects/AES_main/util.cpp > CMakeFiles/AES_main.dir/util.cpp.i

CMakeFiles/AES_main.dir/util.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/AES_main.dir/util.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/frank/CLionProjects/AES_main/util.cpp -o CMakeFiles/AES_main.dir/util.cpp.s

# Object files for target AES_main
AES_main_OBJECTS = \
"CMakeFiles/AES_main.dir/main.cpp.o" \
"CMakeFiles/AES_main.dir/util.cpp.o"

# External object files for target AES_main
AES_main_EXTERNAL_OBJECTS =

AES_main: CMakeFiles/AES_main.dir/main.cpp.o
AES_main: CMakeFiles/AES_main.dir/util.cpp.o
AES_main: CMakeFiles/AES_main.dir/build.make
AES_main: CMakeFiles/AES_main.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/frank/CLionProjects/AES_main/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable AES_main"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/AES_main.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/AES_main.dir/build: AES_main

.PHONY : CMakeFiles/AES_main.dir/build

CMakeFiles/AES_main.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/AES_main.dir/cmake_clean.cmake
.PHONY : CMakeFiles/AES_main.dir/clean

CMakeFiles/AES_main.dir/depend:
	cd /home/frank/CLionProjects/AES_main/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/frank/CLionProjects/AES_main /home/frank/CLionProjects/AES_main /home/frank/CLionProjects/AES_main/cmake-build-debug /home/frank/CLionProjects/AES_main/cmake-build-debug /home/frank/CLionProjects/AES_main/cmake-build-debug/CMakeFiles/AES_main.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/AES_main.dir/depend

