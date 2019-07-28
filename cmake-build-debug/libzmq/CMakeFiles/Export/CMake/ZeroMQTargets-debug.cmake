#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "libzmq" for configuration "Debug"
set_property(TARGET libzmq APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(libzmq PROPERTIES
  IMPORTED_IMPLIB_DEBUG "${_IMPORT_PREFIX}/lib/libzmq.dll.a"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/bin/libzmq.dll"
  )

list(APPEND _IMPORT_CHECK_TARGETS libzmq )
list(APPEND _IMPORT_CHECK_FILES_FOR_libzmq "${_IMPORT_PREFIX}/lib/libzmq.dll.a" "${_IMPORT_PREFIX}/bin/libzmq.dll" )

# Import target "libzmq-static" for configuration "Debug"
set_property(TARGET libzmq-static APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(libzmq-static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_DEBUG "C;CXX;RC"
  IMPORTED_LOCATION_DEBUG "${_IMPORT_PREFIX}/lib/libzmq.a"
  )

list(APPEND _IMPORT_CHECK_TARGETS libzmq-static )
list(APPEND _IMPORT_CHECK_FILES_FOR_libzmq-static "${_IMPORT_PREFIX}/lib/libzmq.a" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
