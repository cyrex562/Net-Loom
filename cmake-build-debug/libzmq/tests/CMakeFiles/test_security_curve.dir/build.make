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
include libzmq/tests/CMakeFiles/test_security_curve.dir/depend.make

# Include the progress variables for this target.
include libzmq/tests/CMakeFiles/test_security_curve.dir/progress.make

# Include the compile flags for this target's objects.
include libzmq/tests/CMakeFiles/test_security_curve.dir/flags.make

libzmq/tests/CMakeFiles/test_security_curve.dir/test_security_curve.cpp.obj: libzmq/tests/CMakeFiles/test_security_curve.dir/flags.make
libzmq/tests/CMakeFiles/test_security_curve.dir/test_security_curve.cpp.obj: libzmq/tests/CMakeFiles/test_security_curve.dir/includes_CXX.rsp
libzmq/tests/CMakeFiles/test_security_curve.dir/test_security_curve.cpp.obj: ../libzmq/tests/test_security_curve.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object libzmq/tests/CMakeFiles/test_security_curve.dir/test_security_curve.cpp.obj"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles\test_security_curve.dir\test_security_curve.cpp.obj -c C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\test_security_curve.cpp

libzmq/tests/CMakeFiles/test_security_curve.dir/test_security_curve.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_security_curve.dir/test_security_curve.cpp.i"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\test_security_curve.cpp > CMakeFiles\test_security_curve.dir\test_security_curve.cpp.i

libzmq/tests/CMakeFiles/test_security_curve.dir/test_security_curve.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_security_curve.dir/test_security_curve.cpp.s"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests\test_security_curve.cpp -o CMakeFiles\test_security_curve.dir\test_security_curve.cpp.s

libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/tweetnacl.c.obj: libzmq/tests/CMakeFiles/test_security_curve.dir/flags.make
libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/tweetnacl.c.obj: libzmq/tests/CMakeFiles/test_security_curve.dir/includes_C.rsp
libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/tweetnacl.c.obj: ../libzmq/src/tweetnacl.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/tweetnacl.c.obj"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles\test_security_curve.dir\__\src\tweetnacl.c.obj   -c C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\src\tweetnacl.c

libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/tweetnacl.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/test_security_curve.dir/__/src/tweetnacl.c.i"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\src\tweetnacl.c > CMakeFiles\test_security_curve.dir\__\src\tweetnacl.c.i

libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/tweetnacl.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/test_security_curve.dir/__/src/tweetnacl.c.s"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\gcc.exe $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\src\tweetnacl.c -o CMakeFiles\test_security_curve.dir\__\src\tweetnacl.c.s

libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/err.cpp.obj: libzmq/tests/CMakeFiles/test_security_curve.dir/flags.make
libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/err.cpp.obj: libzmq/tests/CMakeFiles/test_security_curve.dir/includes_CXX.rsp
libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/err.cpp.obj: ../libzmq/src/err.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/err.cpp.obj"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles\test_security_curve.dir\__\src\err.cpp.obj -c C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\src\err.cpp

libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/err.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_security_curve.dir/__/src/err.cpp.i"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\src\err.cpp > CMakeFiles\test_security_curve.dir\__\src\err.cpp.i

libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/err.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_security_curve.dir/__/src/err.cpp.s"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\src\err.cpp -o CMakeFiles\test_security_curve.dir\__\src\err.cpp.s

libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/random.cpp.obj: libzmq/tests/CMakeFiles/test_security_curve.dir/flags.make
libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/random.cpp.obj: libzmq/tests/CMakeFiles/test_security_curve.dir/includes_CXX.rsp
libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/random.cpp.obj: ../libzmq/src/random.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/random.cpp.obj"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles\test_security_curve.dir\__\src\random.cpp.obj -c C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\src\random.cpp

libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/random.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_security_curve.dir/__/src/random.cpp.i"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\src\random.cpp > CMakeFiles\test_security_curve.dir\__\src\random.cpp.i

libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/random.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_security_curve.dir/__/src/random.cpp.s"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\src\random.cpp -o CMakeFiles\test_security_curve.dir\__\src\random.cpp.s

libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/clock.cpp.obj: libzmq/tests/CMakeFiles/test_security_curve.dir/flags.make
libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/clock.cpp.obj: libzmq/tests/CMakeFiles/test_security_curve.dir/includes_CXX.rsp
libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/clock.cpp.obj: ../libzmq/src/clock.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/clock.cpp.obj"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles\test_security_curve.dir\__\src\clock.cpp.obj -c C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\src\clock.cpp

libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/clock.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_security_curve.dir/__/src/clock.cpp.i"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\src\clock.cpp > CMakeFiles\test_security_curve.dir\__\src\clock.cpp.i

libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/clock.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_security_curve.dir/__/src/clock.cpp.s"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && C:\PROGRA~2\MINGW-~1\I686-8~1.0-P\mingw32\bin\G__~1.EXE $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\src\clock.cpp -o CMakeFiles\test_security_curve.dir\__\src\clock.cpp.s

# Object files for target test_security_curve
test_security_curve_OBJECTS = \
"CMakeFiles/test_security_curve.dir/test_security_curve.cpp.obj" \
"CMakeFiles/test_security_curve.dir/__/src/tweetnacl.c.obj" \
"CMakeFiles/test_security_curve.dir/__/src/err.cpp.obj" \
"CMakeFiles/test_security_curve.dir/__/src/random.cpp.obj" \
"CMakeFiles/test_security_curve.dir/__/src/clock.cpp.obj"

# External object files for target test_security_curve
test_security_curve_EXTERNAL_OBJECTS =

libzmq/bin/test_security_curve.exe: libzmq/tests/CMakeFiles/test_security_curve.dir/test_security_curve.cpp.obj
libzmq/bin/test_security_curve.exe: libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/tweetnacl.c.obj
libzmq/bin/test_security_curve.exe: libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/err.cpp.obj
libzmq/bin/test_security_curve.exe: libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/random.cpp.obj
libzmq/bin/test_security_curve.exe: libzmq/tests/CMakeFiles/test_security_curve.dir/__/src/clock.cpp.obj
libzmq/bin/test_security_curve.exe: libzmq/tests/CMakeFiles/test_security_curve.dir/build.make
libzmq/bin/test_security_curve.exe: libzmq/lib/libtestutil.a
libzmq/bin/test_security_curve.exe: libzmq/lib/libzmq.dll.a
libzmq/bin/test_security_curve.exe: libzmq/lib/libunity.a
libzmq/bin/test_security_curve.exe: libzmq/tests/CMakeFiles/test_security_curve.dir/linklibs.rsp
libzmq/bin/test_security_curve.exe: libzmq/tests/CMakeFiles/test_security_curve.dir/objects1.rsp
libzmq/bin/test_security_curve.exe: libzmq/tests/CMakeFiles/test_security_curve.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Linking CXX executable ..\bin\test_security_curve.exe"
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles\test_security_curve.dir\link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
libzmq/tests/CMakeFiles/test_security_curve.dir/build: libzmq/bin/test_security_curve.exe

.PHONY : libzmq/tests/CMakeFiles/test_security_curve.dir/build

libzmq/tests/CMakeFiles/test_security_curve.dir/clean:
	cd /d C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests && $(CMAKE_COMMAND) -P CMakeFiles\test_security_curve.dir\cmake_clean.cmake
.PHONY : libzmq/tests/CMakeFiles/test_security_curve.dir/clean

libzmq/tests/CMakeFiles/test_security_curve.dir/depend:
	$(CMAKE_COMMAND) -E cmake_depends "MinGW Makefiles" C:\Users\JoshMadden\Documents\GitHub\lwip_refactor C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\libzmq\tests C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests C:\Users\JoshMadden\Documents\GitHub\lwip_refactor\cmake-build-debug\libzmq\tests\CMakeFiles\test_security_curve.dir\DependInfo.cmake --color=$(COLOR)
.PHONY : libzmq/tests/CMakeFiles/test_security_curve.dir/depend
