# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.17

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Disable VCS-based implicit rules.
% : %,v


# Disable VCS-based implicit rules.
% : RCS/%


# Disable VCS-based implicit rules.
% : RCS/%,v


# Disable VCS-based implicit rules.
% : SCCS/s.%


# Disable VCS-based implicit rules.
% : s.%


.SUFFIXES: .hpux_make_needs_suffix_list


# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

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
CMAKE_COMMAND = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake

# The command to remove a file.
RM = /Applications/CLion.app/Contents/bin/cmake/mac/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/mwinger/Desktop/MasterThesis/ckk_s_lab_module_1

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/mwinger/Desktop/MasterThesis/ckk_s_lab_module_1/cmake-build-debug

# Include any dependencies generated for this target.
include CMakeFiles/sealexamples.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/sealexamples.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/sealexamples.dir/flags.make

CMakeFiles/sealexamples.dir/examples.cpp.o: CMakeFiles/sealexamples.dir/flags.make
CMakeFiles/sealexamples.dir/examples.cpp.o: ../examples.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/mwinger/Desktop/MasterThesis/ckk_s_lab_module_1/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/sealexamples.dir/examples.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/sealexamples.dir/examples.cpp.o -c /Users/mwinger/Desktop/MasterThesis/ckk_s_lab_module_1/examples.cpp

CMakeFiles/sealexamples.dir/examples.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/sealexamples.dir/examples.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/mwinger/Desktop/MasterThesis/ckk_s_lab_module_1/examples.cpp > CMakeFiles/sealexamples.dir/examples.cpp.i

CMakeFiles/sealexamples.dir/examples.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/sealexamples.dir/examples.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/mwinger/Desktop/MasterThesis/ckk_s_lab_module_1/examples.cpp -o CMakeFiles/sealexamples.dir/examples.cpp.s

CMakeFiles/sealexamples.dir/ckks_basics.cpp.o: CMakeFiles/sealexamples.dir/flags.make
CMakeFiles/sealexamples.dir/ckks_basics.cpp.o: ../ckks_basics.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/mwinger/Desktop/MasterThesis/ckk_s_lab_module_1/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/sealexamples.dir/ckks_basics.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/sealexamples.dir/ckks_basics.cpp.o -c /Users/mwinger/Desktop/MasterThesis/ckk_s_lab_module_1/ckks_basics.cpp

CMakeFiles/sealexamples.dir/ckks_basics.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/sealexamples.dir/ckks_basics.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/mwinger/Desktop/MasterThesis/ckk_s_lab_module_1/ckks_basics.cpp > CMakeFiles/sealexamples.dir/ckks_basics.cpp.i

CMakeFiles/sealexamples.dir/ckks_basics.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/sealexamples.dir/ckks_basics.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/mwinger/Desktop/MasterThesis/ckk_s_lab_module_1/ckks_basics.cpp -o CMakeFiles/sealexamples.dir/ckks_basics.cpp.s

# Object files for target sealexamples
sealexamples_OBJECTS = \
"CMakeFiles/sealexamples.dir/examples.cpp.o" \
"CMakeFiles/sealexamples.dir/ckks_basics.cpp.o"

# External object files for target sealexamples
sealexamples_EXTERNAL_OBJECTS =

bin/sealexamples: CMakeFiles/sealexamples.dir/examples.cpp.o
bin/sealexamples: CMakeFiles/sealexamples.dir/ckks_basics.cpp.o
bin/sealexamples: CMakeFiles/sealexamples.dir/build.make
bin/sealexamples: /usr/local/lib/libseal-3.6.a
bin/sealexamples: CMakeFiles/sealexamples.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/mwinger/Desktop/MasterThesis/ckk_s_lab_module_1/cmake-build-debug/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable bin/sealexamples"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/sealexamples.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/sealexamples.dir/build: bin/sealexamples

.PHONY : CMakeFiles/sealexamples.dir/build

CMakeFiles/sealexamples.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/sealexamples.dir/cmake_clean.cmake
.PHONY : CMakeFiles/sealexamples.dir/clean

CMakeFiles/sealexamples.dir/depend:
	cd /Users/mwinger/Desktop/MasterThesis/ckk_s_lab_module_1/cmake-build-debug && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/mwinger/Desktop/MasterThesis/ckk_s_lab_module_1 /Users/mwinger/Desktop/MasterThesis/ckk_s_lab_module_1 /Users/mwinger/Desktop/MasterThesis/ckk_s_lab_module_1/cmake-build-debug /Users/mwinger/Desktop/MasterThesis/ckk_s_lab_module_1/cmake-build-debug /Users/mwinger/Desktop/MasterThesis/ckk_s_lab_module_1/cmake-build-debug/CMakeFiles/sealexamples.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/sealexamples.dir/depend

