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
include libzmq/tests/CMakeFiles/testutil.dir/depend.make

# Include the progress variables for this target.
include libzmq/tests/CMakeFiles/testutil.dir/progress.make

# Include the compile flags for this target's objects.
include libzmq/tests/CMakeFiles/testutil.dir/flags.make

libzmq/tests/CMakeFiles/testutil.dir/testutil.cpp.obj: libzmq/tests/CMakeFiles/testutil.dir/flags.make
libzmq/tests/CMakeFiles/testutil.dir/testutil.cpp.obj: libzmq/tests/CMakeFiles/testutil.dir/includes_CXX.rsp
libzmq/tests/CMakeFiles/testutil.dir/testutil.cpp.obj: ../libzmq/tests/testutil.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object libzmq/tests/CMakeFiles/testutil.dir/testutil.cpp.obj"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles\testutil.dir\testutil.cpp.obj -c C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\testutil.cpp

libzmq/tests/CMakeFiles/testutil.dir/testutil.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/testutil.dir/testutil.cpp.i"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\testutil.cpp > CMakeFiles\testutil.dir\testutil.cpp.i

libzmq/tests/CMakeFiles/testutil.dir/testutil.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/testutil.dir/testutil.cpp.s"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\testutil.cpp -o CMakeFiles\testutil.dir\testutil.cpp.s

libzmq/tests/CMakeFiles/testutil.dir/testutil_monitoring.cpp.obj: libzmq/tests/CMakeFiles/testutil.dir/flags.make
libzmq/tests/CMakeFiles/testutil.dir/testutil_monitoring.cpp.obj: libzmq/tests/CMakeFiles/testutil.dir/includes_CXX.rsp
libzmq/tests/CMakeFiles/testutil.dir/testutil_monitoring.cpp.obj: ../libzmq/tests/testutil_monitoring.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object libzmq/tests/CMakeFiles/testutil.dir/testutil_monitoring.cpp.obj"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles\testutil.dir\testutil_monitoring.cpp.obj -c C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\testutil_monitoring.cpp

libzmq/tests/CMakeFiles/testutil.dir/testutil_monitoring.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/testutil.dir/testutil_monitoring.cpp.i"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\testutil_monitoring.cpp > CMakeFiles\testutil.dir\testutil_monitoring.cpp.i

libzmq/tests/CMakeFiles/testutil.dir/testutil_monitoring.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/testutil.dir/testutil_monitoring.cpp.s"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\testutil_monitoring.cpp -o CMakeFiles\testutil.dir\testutil_monitoring.cpp.s

libzmq/tests/CMakeFiles/testutil.dir/testutil_security.cpp.obj: libzmq/tests/CMakeFiles/testutil.dir/flags.make
libzmq/tests/CMakeFiles/testutil.dir/testutil_security.cpp.obj: libzmq/tests/CMakeFiles/testutil.dir/includes_CXX.rsp
libzmq/tests/CMakeFiles/testutil.dir/testutil_security.cpp.obj: ../libzmq/tests/testutil_security.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object libzmq/tests/CMakeFiles/testutil.dir/testutil_security.cpp.obj"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles\testutil.dir\testutil_security.cpp.obj -c C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\testutil_security.cpp

libzmq/tests/CMakeFiles/testutil.dir/testutil_security.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/testutil.dir/testutil_security.cpp.i"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\testutil_security.cpp > CMakeFiles\testutil.dir\testutil_security.cpp.i

libzmq/tests/CMakeFiles/testutil.dir/testutil_security.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/testutil.dir/testutil_security.cpp.s"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\testutil_security.cpp -o CMakeFiles\testutil.dir\testutil_security.cpp.s

libzmq/tests/CMakeFiles/testutil.dir/testutil_unity.cpp.obj: libzmq/tests/CMakeFiles/testutil.dir/flags.make
libzmq/tests/CMakeFiles/testutil.dir/testutil_unity.cpp.obj: libzmq/tests/CMakeFiles/testutil.dir/includes_CXX.rsp
libzmq/tests/CMakeFiles/testutil.dir/testutil_unity.cpp.obj: ../libzmq/tests/testutil_unity.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object libzmq/tests/CMakeFiles/testutil.dir/testutil_unity.cpp.obj"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles\testutil.dir\testutil_unity.cpp.obj -c C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\testutil_unity.cpp

libzmq/tests/CMakeFiles/testutil.dir/testutil_unity.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/testutil.dir/testutil_unity.cpp.i"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\testutil_unity.cpp > CMakeFiles\testutil.dir\testutil_unity.cpp.i

libzmq/tests/CMakeFiles/testutil.dir/testutil_unity.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/testutil.dir/testutil_unity.cpp.s"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\testutil_unity.cpp -o CMakeFiles\testutil.dir\testutil_unity.cpp.s

# Object files for target testutil
testutil_OBJECTS = \
"CMakeFiles/testutil.dir/testutil.cpp.obj" \
"CMakeFiles/testutil.dir/testutil_monitoring.cpp.obj" \
"CMakeFiles/testutil.dir/testutil_security.cpp.obj" \
"CMakeFiles/testutil.dir/testutil_unity.cpp.obj"

# External object files for target testutil
testutil_EXTERNAL_OBJECTS =

libzmq/lib/libtestutil.a: libzmq/tests/CMakeFiles/testutil.dir/testutil.cpp.obj
libzmq/lib/libtestutil.a: libzmq/tests/CMakeFiles/testutil.dir/testutil_monitoring.cpp.obj
libzmq/lib/libtestutil.a: libzmq/tests/CMakeFiles/testutil.dir/testutil_security.cpp.obj
libzmq/lib/libtestutil.a: libzmq/tests/CMakeFiles/testutil.dir/testutil_unity.cpp.obj
libzmq/lib/libtestutil.a: libzmq/tests/CMakeFiles/testutil.dir/build.make
libzmq/lib/libtestutil.a: libzmq/tests/CMakeFiles/testutil.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Linking CXX static library ..\lib\libtestutil.a"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && $(CMAKE_COMMAND) -P CMakeFiles\testutil.dir\cmake_clean_target.cmake
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\testutil.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
libzmq/tests/CMakeFiles/testutil.dir/build: libzmq/lib/libtestutil.a

.PHONY : libzmq/tests/CMakeFiles/testutil.dir/build

libzmq/tests/CMakeFiles/testutil.dir/clean:
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && $(CMAKE_COMMAND) -P CMakeFiles\testutil.dir\cmake_clean.cmake
.PHONY : libzmq/tests/CMakeFiles/testutil.dir/clean

libzmq/tests/CMakeFiles/testutil.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" C:\Users\JoshMadden\Documents\GitHub\lwip_refactor C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests\CMakeFiles\testutil.dir\DependInfo.cmake --color=$(COLOR)
.PHONY : libzmq/tests/CMakeFiles/testutil.dir/depend
