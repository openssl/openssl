# - Try to find m4ri
# Once done this will define
#  M4RI_FOUND - System has m4ri
#  M4RI_INCLUDE_DIRS - The m4ri include directories
#  M4RI_LIBRARIES - The libraries needed to use m4ri
#  M4RI_DEFINITIONS - Compiler switches required for using m4ri

find_package(PkgConfig)
pkg_check_modules(PC_M4RI QUIET m4ri)
set(M4RI_DEFINITIONS ${PC_M4RI_CFLAGS_OTHER})
set(M4RI_VERSION_STRING ${PC_M4RI_VERSION})

find_path(M4RI_INCLUDE_DIR m4ri.h
          HINTS ${PC_LIBM4RI_INCLUDEDIR} ${PC_M4RI_INCLUDE_DIRS}
          PATH_SUFFIXES m4ri)

find_library(M4RI_LIBRARY NAMES m4ri libm4ri
             HINTS ${PC_M4RI_LIBDIR} ${PC_M4RI_LIBRARY_DIRS} )

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set M4RI_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(m4ri
                                  FOUND_VAR M4RI_FOUND
                                  REQUIRED_VARS M4RI_LIBRARY M4RI_INCLUDE_DIR
                                  VERSION_VAR M4RI_VERSION_STRING)

mark_as_advanced(M4RI_INCLUDE_DIR M4RI_LIBRARY M4RI_VERSION_STRING)

set(M4RI_LIBRARIES ${M4RI_LIBRARY})
set(M4RI_INCLUDE_DIRS ${M4RI_INCLUDE_DIR})
