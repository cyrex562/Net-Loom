# CMAKE generated file: DO NOT EDIT!
# Generated by "MinGW Makefiles" Generator, CMake Version 3.14

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

SHELL = cmd.exe

# The CMake executable.
CMAKE_COMMAND = C:\Users\JoshMadden\AppData\Local\JetBrains\Toolbox\apps\CLion\ch-0\192.5728.100\bin\cmake\win\bin\cmake.exe

# The command to remove a file.
RM = C:\Users\JoshMadden\AppData\Local\JetBrains\Toolbox\apps\CLion\ch-0\192.5728.100\bin\cmake\win\bin\cmake.exe -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = C:\Users\JoshMadden\Documents\GitHub\lwip_refactor

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug

# Include any dependencies generated for this target.
include libzmq/tests/CMakeFiles/test_spec_req.dir/depend.make

# Include the progress variables for this target.
include libzmq/tests/CMakeFiles/test_spec_req.dir/progress.make

# Include the compile flags for this target's objects.
include libzmq/tests/CMakeFiles/test_spec_req.dir/flags.make

libzmq/tests/CMakeFiles/test_spec_req.dir/test_spec_req.cpp.obj: libzmq/tests/CMakeFiles/test_spec_req.dir/flags.make
libzmq/tests/CMakeFiles/test_spec_req.dir/test_spec_req.cpp.obj: libzmq/tests/CMakeFiles/test_spec_req.dir/includes_CXX.rsp
libzmq/tests/CMakeFiles/test_spec_req.dir/test_spec_req.cpp.obj: ../libzmq/tests/test_spec_req.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object libzmq/tests/CMakeFiles/test_spec_req.dir/test_spec_req.cpp.obj"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles\test_spec_req.dir\test_spec_req.cpp.obj -c C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\test_spec_req.cpp

libzmq/tests/CMakeFiles/test_spec_req.dir/test_spec_req.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_spec_req.dir/test_spec_req.cpp.i"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\test_spec_req.cpp > CMakeFiles\test_spec_req.dir\test_spec_req.cpp.i

libzmq/tests/CMakeFiles/test_spec_req.dir/test_spec_req.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_spec_req.dir/test_spec_req.cpp.s"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\test_spec_req.cpp -o CMakeFiles\test_spec_req.dir\test_spec_req.cpp.s

# Object files for target test_spec_req
test_spec_req_OBJECTS = \
"CMakeFiles/test_spec_req.dir/test_spec_req.cpp.obj"

# External object files for target test_spec_req
test_spec_req_EXTERNAL_OBJECTS =

libzmq/bin/test_spec_req.exe: libzmq/tests/CMakeFiles/test_spec_req.dir/test_spec_req.cpp.obj
libzmq/bin/test_spec_req.exe: libzmq/tests/CMakeFiles/test_spec_req.dir/build.make
libzmq/bin/test_spec_req.exe: libzmq/lib/libtestutil.a
libzmq/bin/test_spec_req.exe: libzmq/lib/libzmq.dll.a
libzmq/bin/test_spec_req.exe: libzmq/lib/libunity.a
libzmq/bin/test_spec_req.exe: libzmq/tests/CMakeFiles/test_spec_req.dir/linklibs.rsp
libzmq/bin/test_spec_req.exe: libzmq/tests/CMakeFiles/test_spec_req.dir/objects1.rsp
libzmq/bin/test_spec_req.exe: libzmq/tests/CMakeFiles/test_spec_req.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable ..\bin\test_spec_req.exe"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\test_spec_req.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
libzmq/tests/CMakeFiles/test_spec_req.dir/build: libzmq/bin/test_spec_req.exe

.PHONY : libzmq/tests/CMakeFiles/test_spec_req.dir/build

libzmq/tests/CMakeFiles/test_spec_req.dir/clean:
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && $(CMAKE_COMMAND) -P CMakeFiles\test_spec_req.dir\cmake_clean.cmake
.PHONY : libzmq/tests/CMakeFiles/test_spec_req.dir/clean

libzmq/tests/CMakeFiles/test_spec_req.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" C:\Users\JoshMadden\Documents\GitHub\lwip_refactor C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests\CMakeFiles\test_spec_req.dir\DependInfo.cmake --color=$(COLOR)
.PHONY : libzmq/tests/CMakeFiles/test_spec_req.dir/depend

