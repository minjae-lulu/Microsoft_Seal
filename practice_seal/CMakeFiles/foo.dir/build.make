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
CMAKE_SOURCE_DIR = /Users/minjaelee/Desktop/coding/Microsoft_Seal/practice_seal

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/minjaelee/Desktop/coding/Microsoft_Seal/practice_seal

# Include any dependencies generated for this target.
include CMakeFiles/foo.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/foo.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/foo.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/foo.dir/flags.make

CMakeFiles/foo.dir/a.c.o: CMakeFiles/foo.dir/flags.make
CMakeFiles/foo.dir/a.c.o: a.c
CMakeFiles/foo.dir/a.c.o: CMakeFiles/foo.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/minjaelee/Desktop/coding/Microsoft_Seal/practice_seal/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/foo.dir/a.c.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/foo.dir/a.c.o -MF CMakeFiles/foo.dir/a.c.o.d -o CMakeFiles/foo.dir/a.c.o -c /Users/minjaelee/Desktop/coding/Microsoft_Seal/practice_seal/a.c

CMakeFiles/foo.dir/a.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/foo.dir/a.c.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/minjaelee/Desktop/coding/Microsoft_Seal/practice_seal/a.c > CMakeFiles/foo.dir/a.c.i

CMakeFiles/foo.dir/a.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/foo.dir/a.c.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/minjaelee/Desktop/coding/Microsoft_Seal/practice_seal/a.c -o CMakeFiles/foo.dir/a.c.s

CMakeFiles/foo.dir/b.c.o: CMakeFiles/foo.dir/flags.make
CMakeFiles/foo.dir/b.c.o: b.c
CMakeFiles/foo.dir/b.c.o: CMakeFiles/foo.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/Users/minjaelee/Desktop/coding/Microsoft_Seal/practice_seal/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/foo.dir/b.c.o"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT CMakeFiles/foo.dir/b.c.o -MF CMakeFiles/foo.dir/b.c.o.d -o CMakeFiles/foo.dir/b.c.o -c /Users/minjaelee/Desktop/coding/Microsoft_Seal/practice_seal/b.c

CMakeFiles/foo.dir/b.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/foo.dir/b.c.i"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /Users/minjaelee/Desktop/coding/Microsoft_Seal/practice_seal/b.c > CMakeFiles/foo.dir/b.c.i

CMakeFiles/foo.dir/b.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/foo.dir/b.c.s"
	/Library/Developer/CommandLineTools/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /Users/minjaelee/Desktop/coding/Microsoft_Seal/practice_seal/b.c -o CMakeFiles/foo.dir/b.c.s

# Object files for target foo
foo_OBJECTS = \
"CMakeFiles/foo.dir/a.c.o" \
"CMakeFiles/foo.dir/b.c.o"

# External object files for target foo
foo_EXTERNAL_OBJECTS =

foo: CMakeFiles/foo.dir/a.c.o
foo: CMakeFiles/foo.dir/b.c.o
foo: CMakeFiles/foo.dir/build.make
foo: CMakeFiles/foo.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/Users/minjaelee/Desktop/coding/Microsoft_Seal/practice_seal/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Linking C executable foo"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/foo.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/foo.dir/build: foo
.PHONY : CMakeFiles/foo.dir/build

CMakeFiles/foo.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/foo.dir/cmake_clean.cmake
.PHONY : CMakeFiles/foo.dir/clean

CMakeFiles/foo.dir/depend:
	cd /Users/minjaelee/Desktop/coding/Microsoft_Seal/practice_seal && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/minjaelee/Desktop/coding/Microsoft_Seal/practice_seal /Users/minjaelee/Desktop/coding/Microsoft_Seal/practice_seal /Users/minjaelee/Desktop/coding/Microsoft_Seal/practice_seal /Users/minjaelee/Desktop/coding/Microsoft_Seal/practice_seal /Users/minjaelee/Desktop/coding/Microsoft_Seal/practice_seal/CMakeFiles/foo.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/foo.dir/depend
