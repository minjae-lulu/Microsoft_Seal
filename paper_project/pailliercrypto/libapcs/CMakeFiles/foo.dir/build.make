# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

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

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /opt/homebrew/Cellar/cmake/3.22.2/bin/cmake

# The command to remove a file.
RM = /opt/homebrew/Cellar/cmake/3.22.2/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/minjaelee/Desktop/coding/pailliercrypto/libapcs

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/minjaelee/Desktop/coding/pailliercrypto/libapcs

# Include any dependencies generated for this target.
include CMakeFiles/foo.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/foo.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/foo.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/foo.dir/flags.make

CMakeFiles/foo.dir/test.cpp.o: CMakeFiles/foo.dir/flags.make
CMakeFiles/foo.dir/test.cpp.o: test.cpp
CMakeFiles/foo.dir/test.cpp.o: CMakeFiles/foo.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/minjaelee/Desktop/coding/pailliercrypto/libapcs/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/foo.dir/test.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/foo.dir/test.cpp.o -MF CMakeFiles/foo.dir/test.cpp.o.d -o CMakeFiles/foo.dir/test.cpp.o -c /Users/minjaelee/Desktop/coding/pailliercrypto/libapcs/test.cpp

CMakeFiles/foo.dir/test.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/foo.dir/test.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/minjaelee/Desktop/coding/pailliercrypto/libapcs/test.cpp > CMakeFiles/foo.dir/test.cpp.i

CMakeFiles/foo.dir/test.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/foo.dir/test.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/minjaelee/Desktop/coding/pailliercrypto/libapcs/test.cpp -o CMakeFiles/foo.dir/test.cpp.s

CMakeFiles/foo.dir/libapcs.cpp.o: CMakeFiles/foo.dir/flags.make
CMakeFiles/foo.dir/libapcs.cpp.o: libapcs.cpp
CMakeFiles/foo.dir/libapcs.cpp.o: CMakeFiles/foo.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/minjaelee/Desktop/coding/pailliercrypto/libapcs/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object CMakeFiles/foo.dir/libapcs.cpp.o"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/foo.dir/libapcs.cpp.o -MF CMakeFiles/foo.dir/libapcs.cpp.o.d -o CMakeFiles/foo.dir/libapcs.cpp.o -c /Users/minjaelee/Desktop/coding/pailliercrypto/libapcs/libapcs.cpp

CMakeFiles/foo.dir/libapcs.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/foo.dir/libapcs.cpp.i"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/minjaelee/Desktop/coding/pailliercrypto/libapcs/libapcs.cpp > CMakeFiles/foo.dir/libapcs.cpp.i

CMakeFiles/foo.dir/libapcs.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/foo.dir/libapcs.cpp.s"
	/Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/minjaelee/Desktop/coding/pailliercrypto/libapcs/libapcs.cpp -o CMakeFiles/foo.dir/libapcs.cpp.s

# Object files for target foo
foo_OBJECTS = \
"CMakeFiles/foo.dir/test.cpp.o" \
"CMakeFiles/foo.dir/libapcs.cpp.o"

# External object files for target foo
foo_EXTERNAL_OBJECTS =

foo: CMakeFiles/foo.dir/test.cpp.o
foo: CMakeFiles/foo.dir/libapcs.cpp.o
foo: CMakeFiles/foo.dir/build.make
foo: /opt/homebrew/lib/libgmp.dylib
foo: /opt/homebrew/lib/libgmpxx.dylib
foo: ../libhcs/lib/libhcs.so
foo: CMakeFiles/foo.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/minjaelee/Desktop/coding/pailliercrypto/libapcs/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking CXX executable foo"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/foo.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/foo.dir/build: foo
.PHONY : CMakeFiles/foo.dir/build

CMakeFiles/foo.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/foo.dir/cmake_clean.cmake
.PHONY : CMakeFiles/foo.dir/clean

CMakeFiles/foo.dir/depend:
	cd /Users/minjaelee/Desktop/coding/pailliercrypto/libapcs && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/minjaelee/Desktop/coding/pailliercrypto/libapcs /Users/minjaelee/Desktop/coding/pailliercrypto/libapcs /Users/minjaelee/Desktop/coding/pailliercrypto/libapcs /Users/minjaelee/Desktop/coding/pailliercrypto/libapcs /Users/minjaelee/Desktop/coding/pailliercrypto/libapcs/CMakeFiles/foo.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/foo.dir/depend

