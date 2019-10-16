# CMake generated Testfile for 
# Source directory: D:/projects/net_loom/stduuid
# Build directory: D:/projects/net_loom/build/stduuid
# 
# This file includes the relevant testing commands required for 
# testing this directory and lists subdirectories to be tested as well.
add_test(test_uuid "D:/projects/net_loom/build/stduuid/test_uuid.exe" "-r compact")
set_tests_properties(test_uuid PROPERTIES  FAIL_REGULAR_EXPRESSION "Failed \\d+ test cases" PASS_REGULAR_EXPRESSION "Passed all.*" TIMEOUT "120" _BACKTRACE_TRIPLES "D:/projects/net_loom/stduuid/CMakeLists.txt;69;add_test;D:/projects/net_loom/stduuid/CMakeLists.txt;0;")
