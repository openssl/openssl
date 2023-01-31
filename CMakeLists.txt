#
# CMakeLists file for OpenSSL
# Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#

cmake_minimum_required(VERSION 3.14)

project(OpenSSL C CXX)

# Configure the OpenSSL project
if(OPENSSL_CONFIGURE_OPTIONS)
  if (NOT PERL_EXECUTABLE) # Makes PERL_EXECUTABLE overridable
    find_package(Perl 5.10.0 REQUIRED)
  endif()
  execute_process(
    COMMAND ${CMAKE_COMMAND} -E env "BUILDFILE=openssl.cmake" ${PERL_EXECUTABLE} Configure ${OPENSSL_CONFIGURE_OPTIONS}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    RESULT_VARIABLE OPENSSL_CONFIGURE_RESULT
    COMMAND_ECHO STDOUT
  )
  if(NOT (${OPENSSL_CONFIGURE_RESULT} EQUAL "0"))
    message(FATAL_ERROR "Failed to configure OpenSSL with error: ${OPENSSL_CONFIGURE_RESULT}")
  endif()
endif()

# Include the generated CMake config.
include(openssl.cmake)

# Process object library targets.
foreach(object_target ${OPENSSL_OBJECT_TARGETS})
  add_library(ossl_${object_target}_object OBJECT ${OPENSSL_ASM_SOURCES_${object_target}}
                                                  ${OPENSSL_SOURCES_${object_target}})
  target_link_libraries(ossl_${object_target}_object PRIVATE ${OPENSSL_LINK_LIBRARIES_${object_target}})
endforeach()

# Add static library targets.
foreach(static_target ${OPENSSL_STATIC_TARGETS})
  add_library(openssl_${static_target} STATIC ${OPENSSL_ASM_SOURCES_${static_target}}
                                              ${OPENSSL_SOURCES_${static_target}})
  target_link_libraries(openssl_${static_target} PRIVATE ${OPENSSL_LINK_LIBRARIES_${static_target}} ${OPENSSL_OBJECT_DEPENDS_${static_target}})
  set_target_properties(openssl_${static_target} PROPERTIES OUTPUT_NAME "${static_target}" PREFIX "") # prevent lib prefix
  if(OPENSSL_POSITION_INDEPENDENT_CODE)
    set_property(TARGET openssl_${static_target} PROPERTY POSITION_INDEPENDENT_CODE ON)
  endif()
  if(OPENSSL_DEPENDENCIES_${static_target})
    add_dependencies(openssl_${static_target} ${OPENSSL_DEPENDENCIES_${static_target}})
  endif()
  add_library(OpenSSL::${static_target} ALIAS openssl_${static_target})
endforeach()

# Add shared library targets.
foreach(shared_target ${OPENSSL_SHARED_TARGETS})
  add_library(openssl_${shared_target} SHARED ${OPENSSL_ASM_SOURCES_${shared_target}}
                                              ${OPENSSL_SOURCES_${shared_target}}
                                              ${OPENSSL_LINK_DEFS_${shared_target}})
  target_link_libraries(openssl_${shared_target} PRIVATE ${OPENSSL_LINK_LIBRARIES_${shared_target}})
  set_target_properties(openssl_${shared_target} PROPERTIES OUTPUT_NAME "${shared_target}" PREFIX "") # prevent lib prefix
  if(OPENSSL_POSITION_INDEPENDENT_CODE)
    set_property(TARGET openssl_${shared_target} PROPERTY POSITION_INDEPENDENT_CODE ON)
  endif()
  if(OPENSSL_HAS_VERSION_SCRIPT_SUPPORT)
    foreach(lddef ${OPENSSL_LINK_DEFS_${shared_target}})
      set_property(TARGET openssl_${shared_target} APPEND_STRING
                    PROPERTY LINK_FLAGS " -Wl,--version-script=${lddef}")
      set_target_properties(openssl_${shared_target} PROPERTIES LINK_DEPENDS ${lddef})
    endforeach()
  endif()
  if(OPENSSL_DEPENDENCIES_${shared_target})
    add_dependencies(openssl_${shared_target} ${OPENSSL_DEPENDENCIES_${shared_target}})
  endif()
  add_library(OpenSSL::${shared_target} ALIAS openssl_${shared_target})
endforeach()

# Add DSO module targets.
foreach(dso_target ${OPENSSL_DSO_TARGETS})
  add_library(openssl_${dso_target} MODULE ${OPENSSL_ASM_SOURCES_${dso_target}}
                                           ${OPENSSL_SOURCES_${dso_target}}
                                           ${OPENSSL_LINK_DEFS_${dso_target}})
  target_link_libraries(openssl_${dso_target} PRIVATE ${OPENSSL_LINK_LIBRARIES_${dso_target}})
  set_target_properties(openssl_${dso_target} PROPERTIES OUTPUT_NAME "${dso_target}" PREFIX "") # prevent lib prefix
  if(OPENSSL_POSITION_INDEPENDENT_CODE)
    set_property(TARGET openssl_${dso_target} PROPERTY POSITION_INDEPENDENT_CODE ON)
  endif()
  if(OPENSSL_HAS_VERSION_SCRIPT_SUPPORT)
    foreach(lddef ${OPENSSL_LINK_DEFS_${dso_target}})
      set_property(TARGET openssl_${dso_target} APPEND_STRING
                    PROPERTY LINK_FLAGS " -Wl,--version-script=${lddef}")
      set_target_properties(openssl_${dso_target} PROPERTIES LINK_DEPENDS ${lddef})
    endforeach()
  endif()
  if(OPENSSL_DEPENDENCIES_${dso_target})
    add_dependencies(openssl_${dso_target} ${OPENSSL_DEPENDENCIES_${dso_target}})
  endif()
  add_library(OpenSSL::${dso_target} ALIAS openssl_${dso_target})
endforeach()

# Add binary executable targets.
foreach(bin_target ${OPENSSL_BIN_TARGETS})
  add_executable(openssl_${bin_target} ${OPENSSL_ASM_SOURCES_${bin_target}}
                                       ${OPENSSL_SOURCES_${bin_target}})
  target_link_libraries(openssl_${bin_target} PRIVATE ${OPENSSL_LINK_LIBRARIES_${bin_target}})
  set_target_properties(openssl_${bin_target} PROPERTIES OUTPUT_NAME "${bin_target}")
  if(OPENSSL_POSITION_INDEPENDENT_CODE)
    set_property(TARGET openssl_${bin_target} PROPERTY POSITION_INDEPENDENT_CODE ON)
  endif()
  if(OPENSSL_DEPENDENCIES_${bin_target})
    add_dependencies(openssl_${bin_target} ${OPENSSL_DEPENDENCIES_${bin_target}})
  endif()
  add_executable(OpenSSL::${bin_target} ALIAS openssl_${bin_target})
endforeach()

# Add custom targets for generating docs.
add_custom_target(openssl_pod_docs DEPENDS ${GENERATE_POD_DOCS})
add_custom_target(openssl_html_docs DEPENDS openssl_pod_docs ${GENERATE_HTML_DOCS})
add_custom_target(openssl_man_docs DEPENDS ${GENERATE_MAN_DOCS})
add_custom_target(openssl_docs DEPENDS openssl_man_docs openssl_html_docs)
