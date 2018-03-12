cmake_minimum_required(VERSION 3.3 FATAL_ERROR)
cmake_policy(SET CMP0063 NEW)
if("${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}" STRGREATER "3.8")
  cmake_policy(SET CMP0069 NEW)
endif()

# cmake setup
set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# project info
project(picnic C CXX)

set(PICNIC_MAJOR_VERSION 1)
set(PICNIC_MINOR_VERSION 0)
set(PICNIC_PATCH_VERSION 0)
set(PICNIC_VERSION ${PICNIC_MAJOR_VERSION}.${PICNIC_MINOR_VERSION}.${PICNIC_PATCH_VERSION})

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE "RelWithDebInfo" CACHE STRING "Choose the type of build." FORCE)
endif()

# set required C standard version
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# required fuctions
include(CheckSIMD)
include(CheckFunctionExists)
include(CheckCCompilerFlag)
include(CheckIncludeFiles)
include(CheckSymbolExists)

# required libraries
find_package(OpenSSL)
find_package(m4ri 20140914)

if(APPLE)
  find_path(SECRUTY_INCLUDE_DIR Security/Security.h)
  find_library(SECURITY_LIBRARY Security)
  mark_as_advanced(SECURITY_INCLUDE_DIR SECURITY_LIBRARY)
  set(HAVE_SECURITY_FRAMEWORK TRUE)
endif()

# check headers
check_include_files(sys/auxv.h HAVE_SYS_AUXV_H)
check_include_files(asm/hwcap.h HAVE_ASM_HWCAP_H)
check_include_files(sys/random.h HAVE_SYS_RANDOM_H)

# check availability of some functions
check_symbol_exists(aligned_alloc stdlib.h HAVE_ALIGNED_ALLOC)
check_symbol_exists(posix_memalign stdlib.h HAVE_POSIX_MEMALIGN)
check_symbol_exists(memalign malloc.h HAVE_MEMALIGN)
check_symbol_exists(getrandom sys/random.h HAVE_GETRANDOM)

# check supported compiler flags
check_c_compiler_flag(-march=native CC_SUPPORTS_MARCH_NATIVE)
check_c_compiler_flag(-mtune=native CC_SUPPORTS_MTUNE_NATIVE)
check_c_compiler_flag(-O3 CC_SUPPORTS_03)
check_c_compiler_flag(-Wall CC_SUPPORTS_WALL)
check_c_compiler_flag(-Wextra CC_SUPPORTS_WEXTRA)
check_c_compiler_flag(-fomit-frame-pointer CC_SUPPORTS_FOMIT_FRAME_POINTER)
check_c_compiler_flag(-fvisibility=hidden CC_SUPPORTS_FVISIBILITY)

#check SIMD instructions set
check_simd(SSE2 CC_SUPPORTS_SSE2)
check_simd(SSE4_1 CC_SUPPORTS_SSE4_1)
check_simd(AVX2 CC_SUPPORTS_AVX2)
check_simd(NEON CC_SUPPORTS_NEON)

# user-settable options
if(APPLE AND ${CMAKE_C_COMPILER_ID} STREQUAL "GNU")
# workaround for broken -march=native support on some versions of GCC on OS X.
set(DEFAULT_WITH_MARCH_NATIVE OFF)
else()
set(DEFAULT_WITH_MARCH_NATIVE ON)
endif()

set(WITH_SIMD_OPT ON CACHE BOOL "Enable optimizations via SIMD.")
set(WITH_AVX2 ON CACHE BOOL "Use AVX2 if available.")
set(WITH_SSE2 ON CACHE BOOL "Use SSE2 if available.")
set(WITH_SSE4_1 ON CACHE BOOL "Use SSE4.1 if available.")
set(WITH_NEON ON CACHE BOOL "Use NEON if available.")
set(WITH_MARCH_NATIVE ${DEFAULT_WITH_MARCH_NATIVE} CACHE BOOL "Build with -march=native -mtune=native (if supported).")
set(WITH_LTO ON CACHE BOOL "Enable link-time optimization (if supported).")
set(WITH_MUL_M4RI ON CACHE BOOL "Use methods of four russians for matrix multiplication.")
set(SHA3_IMPL "opt64" CACHE STRING "Select SHA3 implementation.")
set(ENABLE_VERBOSE_OUTPUT OFF CACHE BOOL "Enable verbose output.")
set(ENABLE_DETAILED_TIMINGS OFF CACHE BOOL "Enable detail timings.")
set(WITH_REDUCED_LINEAR_LAYER ON CACHE BOOL "Enable precomputation of round key.")
set(WITH_CUSTOM_INSTANCES OFF CACHE BOOL "Enable large and custom LowMC instances.")

# do not build with -rdynamic
string(REGEX REPLACE "-rdynamic" "" CMAKE_EXE_LINKER_FLAGS
  "${CMAKE_EXE_LINKER_FLAGS}")
string(REGEX REPLACE "-rdynamic" "" CMAKE_SHARED_LIBRARY_LINK_C_FLAGS
  "${CMAKE_SHARED_LIBRARY_LINK_C_FLAGS}")
string(REGEX REPLACE "-rdynamic" "" CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS
  "${CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS}")

# build with -Wall and -Wextra if supported
if(CC_SUPPORTS_WALL)
  add_compile_options("-Wall")
endif()
if(CC_SUPPORTS_WEXTRA)
  add_compile_options("-Wextra")
endif()

# enable -march=native -mtune=native if supported
if(WITH_MARCH_NATIVE)
  if (CC_SUPPORTS_MARCH_NATIVE)
    add_compile_options("-march=native")
  endif()
  if (CC_SUPPORTS_MTUNE_NATIVE)
    add_compile_options("-mtune=native")
  endif()
endif()

# enable LTO if supported
if(WITH_LTO)
  if ("${CMAKE_MAJOR_VERSION}.${CMAKE_MINOR_VERSION}" STRLESS "3.9")
    if(CMAKE_COMPILER_IS_GNUCC)
      set(CMAKE_AR "gcc-ar")
      set(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> qcs <TARGET> <LINK_FLAGS> <OBJECTS>")
      set(CMAKE_C_ARCHIVE_FINISH true)
      set(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> qcs <TARGET> <LINK_FLAGS> <OBJECTS>")
      set(CMAKE_CXX_ARCHIVE_FINISH true)
    endif()

    check_c_compiler_flag(-flto CC_SUPPORTS_FLTO)
    if(CC_SUPPORTS_FLTO)
      add_compile_options(-flto)
      set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -flto")
    endif()
  else()
    include(CheckIPOSupported)
    check_ipo_supported(RESULT LTO_SUPPORTED OUTPUT LTO_OUTPUT)
    if (LTO_SUPPORTED)
      set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)
    else()
      message(WARNING "IPO is not supported: ${LTO_OUTPUT}")
    endif()
  endif()
endif()

# enable -O3
if(CC_SUPPORTS_03)
  add_compile_options(-O3)
endif()
# enable -fomit-frame-pointer
if(CC_SUPPORTS_FOMIT_FRAME_POINTER)
  add_compile_options(-fomit-frame-pointer)
endif()

configure_file(config.h.in config.h)

include_directories(${CMAKE_CURRENT_BINARY_DIR} ${CMAKE_CURRENT_SOURCE_DIR} sha3 "sha3/${SHA3_IMPL}")

list(APPEND SHA3_SOURCES
    sha3/KeccakHash.c
    sha3/KeccakSponge.c)

if(${SHA3_IMPL} STREQUAL "avx2")
  list(APPEND SHA3_SOURCES sha3/avx2/KeccakP-1600-AVX2.cpp)
elseif(${SHA3_IMPL} STREQUAL "opt64")
  list(APPEND SHA3_SOURCES sha3/opt64/KeccakP-1600-opt64.c)
elseif(${SHA3_IMPL} STREQUAL "armv8a-neon")
  list(APPEND SHA3_SOURCES sha3/armv8a-neon/KeccakP-1600-armv8a-neon.s)
  set_property(SOURCE sha3/armv8a-neon/KeccakP-1600-armv8a-neon.s PROPERTY LANGUAGE C)
else()
  message(FATAL_ERROR "Unknown SHA3 implementation")
endif()

list(APPEND PICNIC_SOURCES
    aligned_alloc.c
    bitstream.c
    cpu.c
    io.c
    kdf_shake.c
    lowmc.c
    lowmc_pars.c
    lowmc_128_128_20.c
    lowmc_192_192_30.c
    lowmc_256_256_38.c
    mpc.c
    mpc_lowmc.c
    mzd_additional.c
    picnic.c
    picnic_impl.c
    randomness.c
    timing.c)

if(WITH_CUSTOM_INSTANCES)
  list(APPEND PICNIC_SOURCES lowmc_512_512_38.c)
endif()

# shared library
add_library(picnic SHARED ${PICNIC_SOURCES} ${SHA3_SOURCES})
set_target_properties(picnic PROPERTIES VERSION ${PICNIC_VERSION} SOVERSION ${PICNIC_MAJOR_VERSION})
if(MSVC)
  set_target_properties(picnic PROPERTIES OUTPUT_NAME libpicnic)
endif()

# static library
add_library(picnic_static STATIC ${PICNIC_SOURCES} ${SHA3_SOURCES})
if(MSVC)
  set_target_properties(picnic_static PROPERTIES OUTPUT_NAME libpicnic_static)
endif()
target_compile_definitions(picnic_static PUBLIC PICNIC_STATIC_DEFINE)

function(apply_picnic_options lib)
  set_target_properties(${lib} PROPERTIES C_VISIBILITY_PRESET hidden)

  target_compile_definitions(${lib} PRIVATE HAVE_CONFIG_H)
  target_compile_definitions(${lib} PRIVATE WITH_LOWMC_128_128_20
    WITH_LOWMC_192_192_30 WITH_LOWMC_256_256_38)
  if(ENABLE_DETAILED_TIMINGS)
    target_compile_definitions(${lib} PRIVATE WITH_DETAILED_TIMING)
  endif()
  if(WITH_SIMD_OPT)
    target_compile_definitions(${lib} PRIVATE WITH_OPT)
    if(CC_SUPPORTS_SSE2 AND WITH_SSE2)
      target_compile_definitions(${lib} PRIVATE WITH_SSE2)
      if(CC_SUPPORTS_SSE4_1 AND WITH_SSE4_1)
        target_compile_definitions(${lib} PRIVATE WITH_SSE4_1)
      endif()
      if(CC_SUPPORTS_AVX2 AND WITH_AVX2)
        target_compile_definitions(${lib} PRIVATE WITH_AVX2)
      endif()
    endif()
    if(CC_SUPPORTS_NEON AND WITH_NEON)
      target_compile_definitions(${lib} PRIVATE WITH_NEON)
    endif()
  endif()
  if(WITH_MUL_M4RI)
    target_compile_definitions(${lib} PRIVATE MUL_M4RI)
  endif()
  if(WITH_REDUCED_LINEAR_LAYER)
    target_compile_definitions(${lib} PRIVATE REDUCED_LINEAR_LAYER)
  endif()
  if(WITH_CUSTOM_INSTANCES)
    target_compile_definitions(${lib} PRIVATE WITH_CUSTOM_INSTANCES)
    target_compile_definitions(${lib} PRIVATE WITH_LOWMC_512_512_39)
  endif()

  if(WIN32)
    target_compile_definitions(${lib} PRIVATE "_WIN32_WINNT=0x0601")
    target_link_libraries(${lib} bcrypt)
  endif()

  if(APPLE)
    target_include_directories(${lib} PRIVATE ${SECURTY_INCLUDE_DIR})
    target_link_libraries(${lib} PRIVATE ${SECURITY_LIBRARY})
  endif()
endfunction(apply_picnic_options)

apply_picnic_options(picnic)
apply_picnic_options(picnic_static)

if (WIN32)
  target_compile_definitions(picnic PRIVATE "PICNIC_EXPORT=__declspec(dllexport)")
else()
  target_compile_definitions(picnic PRIVATE "PICNIC_EXPORT=__attribute__((visibility(\"default\")))")
  if (CC_SUPPORTS_FVISIBILITY)
    target_compile_options(picnic PRIVATE -fvisibility=hidden)
  endif()
endif()
target_compile_definitions(picnic_static PRIVATE PICNIC_EXPORT=)

# genparams executable
if(M4RI_FOUND AND OPENSSL_FOUND)
  add_executable(genparams tools/genparams.c)
  target_link_libraries(genparams ${M4RI_LIBRARY} OpenSSL::Crypto)
  target_compile_definitions(genparams PRIVATE HAVE_CONFIG_H)
  if(WITH_REDUCED_LINEAR_LAYER)
    target_compile_definitions(genparams PRIVATE REDUCED_LINEAR_LAYER)
  endif()
endif()

# visualize_signature executable
add_executable(visualize_signature tools/visualize_signature.c)
target_link_libraries(visualize_signature picnic_static)
target_compile_definitions(visualize_signature PRIVATE HAVE_CONFIG_H PICNIC_STATIC)

# bench executable
add_executable(bench tools/bench.c)
target_link_libraries(bench picnic)
target_compile_definitions(bench PRIVATE HAVE_CONFIG_H)
if(ENABLE_DETAILED_TIMINGS)
  target_compile_definitions(bench PRIVATE WITH_DETAILED_TIMING)
endif()
if(ENABLE_VERBOSE_OUTPUT)
  target_compile_definitions(bench PRIVATE VERBOSE)
endif()

# example executable
add_executable(example tools/example.c)
target_link_libraries(example picnic)
target_compile_definitions(example PRIVATE HAVE_CONFIG_H)

foreach(target IN ITEMS L1_FS L1_UR L3_FS L3_UR L5_FS L5_UR)
  add_library("picnic_${target}" STATIC "${target}/sign.c")
  target_include_directories("picnic_${target}" PRIVATE "${target}")
  target_link_libraries("picnic_${target}" picnic)
endforeach(target)

# tests
enable_testing()
add_subdirectory(tests)
