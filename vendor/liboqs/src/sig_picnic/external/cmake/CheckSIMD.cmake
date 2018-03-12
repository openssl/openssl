set(DIR_OF_THIS ${CMAKE_CURRENT_LIST_DIR})

macro(CHECK_SIMD INS VARIABLE)
  if(NOT DEFINED "${VARIABLE}" OR "x${${VARIABLE}}" STREQUAL "x${VARIABLE}")
    set(MACRO_CHECK_INS_DEFINITIONS
      "-D${INS} ${CMAKE_REQUIRED_FLAGS}")
    if(NOT CMAKE_REQUIRED_QUIET)
      message(STATUS "Looking for SIMD instruction set ${INS}")
    endif()
    if(CMAKE_REQUIRED_LIBRARIES)
      set(CHECK_INS_EXISTS_ADD_LIBRARIES
        LINK_LIBRARIES ${CMAKE_REQUIRED_LIBRARIES})
    else()
      set(CHECK_INS_EXISTS_ADD_LIBRARIES)
    endif()
    if(CMAKE_REQUIRED_INCLUDES)
      set(CHECK_INS_EXISTS_ADD_INCLUDES
        "-DINCLUDE_DIRECTORIES:STRING=${CMAKE_REQUIRED_INCLUDES}")
    else()
      set(CHECK_INS_EXISTS_ADD_INCLUDES)
    endif()

    if(CMAKE_C_COMPILER_LOADED)
      set(_cfe_source ${DIR_OF_THIS}/check-simd.c)
    else()
      message(FATAL_ERROR "CHECK_SIMD needs C language enabled")
    endif()

    try_compile(${VARIABLE}
      ${CMAKE_BINARY_DIR}
      ${_cfe_source}
      COMPILE_DEFINITIONS ${CMAKE_REQUIRED_DEFINITIONS}
      ${CHECK_INS_EXISTS_ADD_LIBRARIES}
      CMAKE_FLAGS -DCOMPILE_DEFINITIONS:STRING=${MACRO_CHECK_INS_DEFINITIONS}
      "${CHECK_INS_EXISTS_ADD_INCLUDES}"
      OUTPUT_VARIABLE OUTPUT)
    unset(_cfe_source)

    if(${VARIABLE})
      set(${VARIABLE} 1 CACHE INTERNAL "Have instruction set ${INS}")
      if(NOT CMAKE_REQUIRED_QUIET)
        message(STATUS "Looking for instruction set ${INS} - found")
      endif()
      file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeOutput.log
        "Determining if the instruction set ${INS} exists passed with the following output:\n"
        "${OUTPUT}\n\n")
    else()
      if(NOT CMAKE_REQUIRED_QUIET)
        message(STATUS "Looking for instruction set ${INS} - not found")
      endif()
      set(${VARIABLE} "" CACHE INTERNAL "Have instruction set ${INS}")
      file(APPEND ${CMAKE_BINARY_DIR}${CMAKE_FILES_DIRECTORY}/CMakeError.log
        "Determining if the instruction set ${INS} exists failed with the following output:\n"
        "${OUTPUT}\n\n")
    endif()
  endif()
endmacro()
