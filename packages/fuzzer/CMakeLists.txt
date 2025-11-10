cmake_minimum_required(VERSION 3.15)

project(jazzerjs)

find_package(Patch REQUIRED)

set(CMAKE_CXX_STANDARD 17) # mostly supported since GCC 7
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(LLVM_ENABLE_LLD TRUE)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
# Avoid warning about DOWNLOAD_EXTRACT_TIMESTAMP in CMake 3.24:
if(CMAKE_VERSION VERSION_GREATER_EQUAL "3.24.0")
  cmake_policy(SET CMP0135 NEW)
endif()

# To help with development, let's write compile_commands.json unconditionally.
set(CMAKE_EXPORT_COMPILE_COMMANDS 1)

# As per the cmake-js README, we need the following to build on Windows:
if(MSVC
   AND CMAKE_JS_NODELIB_DEF
   AND CMAKE_JS_NODELIB_TARGET)
  # Generate node.lib
  execute_process(
    COMMAND ${CMAKE_AR} /def:${CMAKE_JS_NODELIB_DEF}
            /out:${CMAKE_JS_NODELIB_TARGET} ${CMAKE_STATIC_LINKER_FLAGS})
endif()

# CMAKE_JS_INC, containing nodejs API headers, is only set by invocations via
# cmake-js, manually set it when executed in other environments like IDEs.
if (NOT CMAKE_JS_INC)
  execute_process(
    COMMAND npx cmake-js print-cmakejs-include
    OUTPUT_VARIABLE CMAKE_JS_INC)
endif ()

# Define the libFuzzer target for the jazzerjs shared library (no main)
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(LIBFUZZER_TARGET "clang_rt.fuzzer_no_main-x86_64")
  set(LIBFUZZER_STATIC_LIB_PATH "lib/linux/lib${LIBFUZZER_TARGET}.a")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set(LIBFUZZER_TARGET "clang_rt.fuzzer_no_main_osx")
  set(LIBFUZZER_STATIC_LIB_PATH "lib/darwin/lib${LIBFUZZER_TARGET}.a")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MT /EHsc")
  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT /EHsc")
  set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd /EHsc")
  set(LIBFUZZER_TARGET "clang_rt.fuzzer_no_main-x86_64")
  set(LIBFUZZER_STATIC_LIB_PATH "lib/windows/${LIBFUZZER_TARGET}.lib")
endif()

# Define the libFuzzer target for standalone fuzzing executables (with main)
# <--- NEW/MODIFIED SECTION START
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(FUZZ_TARGET_LIBFUZZER_TARGET "clang_rt.fuzzer-x86_64")
  set(FUZZ_TARGET_LIBFUZZER_STATIC_LIB_PATH "lib/linux/lib${FUZZ_TARGET_LIBFUZZER_TARGET}.a")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  set(FUZZ_TARGET_LIBFUZZER_TARGET "clang_rt.fuzzer_osx")
  set(FUZZ_TARGET_LIBFUZZER_STATIC_LIB_PATH "lib/darwin/lib${FUZZ_TARGET_LIBFUZZER_TARGET}.a")
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  set(FUZZ_TARGET_LIBFUZZER_TARGET "clang_rt.fuzzer-x86_64")
  set(FUZZ_TARGET_LIBFUZZER_STATIC_LIB_PATH "lib/windows/${FUZZ_TARGET_LIBFUZZER_TARGET}.lib")
endif()
# <--- NEW/MODIFIED SECTION END

# Enable the functionality of Node-API version 4 and disable everything added
# later, so that we don't accidentally break compatibility with older versions
# of Node (see https://nodejs.org/api/n-api.html#node-api-version-matrix).
#
# Note that prebuild recommends in its README to use ${napi_build_version} here,
# but the variable is only set when cmake-js is invoked via prebuild (in which
# case the API version is taken from "binary.napi_versions" in package.json).
# Since we want the build to work in other cases as well, let's just use a
# constant. (There is currently no point in a dynamic setting anyway since we
# specify the oldest version that we're compatible with, and Node-API's ABI
# stability guarantees that this version is available in all future Node-API
# releases.)
add_definitions(-DNAPI_VERSION=4)

# Collect source files for the main jazzerjs shared library
# <--- MODIFIED SECTION START
file(GLOB JAZZERJS_SOURCES
     RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}" # Use RELATIVE path for list removal
     "*.cpp" "*.h" "shared/*.cpp" "shared/*.h")

# Exclude fuzz_target.cpp from the main shared library build
list(REMOVE_ITEM JAZZERJS_SOURCES "fuzz_target.cpp")

add_library(${PROJECT_NAME} SHARED ${JAZZERJS_SOURCES} ${CMAKE_JS_SRC})
# <--- MODIFIED SECTION END

set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_JS_INC})
target_link_libraries(${PROJECT_NAME} ${CMAKE_JS_LIB})

# We're not sure why but sometimes systems don't end up setting LLVM_TARGET_TRIPLE used in llvm's cmake to eventually
# set COMPILER_RT_DEFAULT_TARGET which is necessary for compiler-rt to build
# So this will either take it from an envvar or try to set it to a sane value until we can figure out why it's broken
if(NOT DEFINED ENV{COMPILER_RT_DEFAULT_TARGET_TRIPLE})
  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    execute_process(COMMAND ${CMAKE_CXX_COMPILER} "-print-target-triple" OUTPUT_VARIABLE COMPILER_RT_DEFAULT_TARGET_TRIPLE)
  elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    execute_process(COMMAND ${CMAKE_CXX_COMPILER} "-dumpmachine" OUTPUT_VARIABLE COMPILER_RT_DEFAULT_TARGET_TRIPLE)
  elseif(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    # pulled from https://github.com/llvm/llvm-project/blob/main/llvm/cmake/modules/GetHostTriple.cmake
    if( CMAKE_C_COMPILER_ARCHITECTURE_ID MATCHES "ARM64.*" )
      set( COMPILER_RT_DEFAULT_TARGET_TRIPLE "aarch64-pc-windows-msvc" )
    elseif( CMAKE_C_COMPILER_ARCHITECTURE_ID MATCHES "ARM.*" )
      set( COMPILER_RT_DEFAULT_TARGET_TRIPLE "armv7-pc-windows-msvc" )
    elseif( CMAKE_C_COMPILER_ARCHITECTURE_ID STREQUAL "x64" )
      set( COMPILER_RT_DEFAULT_TARGET_TRIPLE "x86_64-pc-windows-msvc" )
    elseif( CMAKE_C_COMPILER_ARCHITECTURE_ID STREQUAL "X86" )
      set( COMPILER_RT_DEFAULT_TARGET_TRIPLE "i686-pc-windows-msvc" )
    elseif( CMAKE_SIZEOF_VOID_P EQUAL 8 )
      set( COMPILER_RT_DEFAULT_TARGET_TRIPLE "x86_64-pc-windows-msvc" )
    else()
      set( COMPILER_RT_DEFAULT_TARGET_TRIPLE "i686-pc-windows-msvc" )
    endif()
  endif()
  # strip whitespace because newlines from the shell calls will break the cmake call
  string(STRIP ${COMPILER_RT_DEFAULT_TARGET_TRIPLE} COMPILER_RT_DEFAULT_TARGET_TRIPLE)
  message(STATUS "COMPILER_RT_DEFAULT_TARGET_TRIPLE not set, using ${COMPILER_RT_DEFAULT_TARGET_TRIPLE}")
endif()

# Download and build compiler-rt, which contains libfuzzer.
include(ExternalProject)
ExternalProject_Add(
  compiler-rt
  URL https://github.com/CodeIntelligenceTesting/llvm-project-jazzer/archive/refs/tags/2023-04-25.tar.gz
  URL_HASH
    SHA256=200b32c897b1171824462706f577d7f1d6175da602eccfe570d2dceeac11d490
  SOURCE_SUBDIR compiler-rt
  CMAKE_ARGS # compiler-rt usually initializes the sanitizer runtime by means of
             # a pointer in the .preinit_array section; since .preinit_array
             # isn't supported for shared objects like our Node plugin, disable
             # it here.
             -DCMAKE_CXX_FLAGS="-DSANITIZER_CAN_USE_PREINIT_ARRAY=0"
             # Build AddressSanitizer and UndefinedBehaviorSanitizer alongside libFuzzer.
             # These are crucial for effective fuzzing.
             -DCOMPILER_RT_SANITIZERS_TO_BUILD="address;undefined" # <--- MODIFIED
             # Don't build libc++ into the fuzzer; our own code is C++ as well,
             # so we're going to link against a C++ runtime anyway.
             -DCOMPILER_RT_USE_LIBCXX=OFF
             # Use the same build type as the parent project.
             -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
             -DCOMPILER_RT_DEFAULT_TARGET_TRIPLE=${COMPILER_RT_DEFAULT_TARGET_TRIPLE}
             -DLLVM_CMAKE_DIR=<SOURCE_DIR>/llvm/cmake/modules
             # We need both libfuzzer (with main) and libfuzzer_no_main.
  BUILD_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --target
                ${LIBFUZZER_TARGET} ${FUZZ_TARGET_LIBFUZZER_TARGET} # <--- MODIFIED
  # Skip the install step because it tries to copy files to a hardcoded path in
  # "/usr".
  INSTALL_COMMAND ""
  # Tell CMake about the libfuzzer libraries that are built as part of the
  # external project. Some CMake generators fail if we later depend on the
  # libraries without declaring them here (including ninja).
  BUILD_BYPRODUCTS <BINARY_DIR>/${LIBFUZZER_STATIC_LIB_PATH}
                   <BINARY_DIR>/${FUZZ_TARGET_LIBFUZZER_STATIC_LIB_PATH}) # <--- MODIFIED

# Make our plugin depend on and link against libfuzzer.
add_dependencies(${PROJECT_NAME} compiler-rt)
ExternalProject_Get_Property(compiler-rt BINARY_DIR)
ExternalProject_Get_Property(compiler-rt SOURCE_DIR)
target_include_directories(${PROJECT_NAME}
                           PRIVATE ${SOURCE_DIR}/compiler-rt/lib)

# We may want to include additional libraries here. For example,
# libclang_rt.fuzzer_interceptors-x86_64.a contains
# https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/fuzzer/FuzzerInterceptors.cpp,
# i.e., fuzzer-friendly overrides for some common libc functions. However, there
# is a challenge with this particular library: we're not in the binary, so we
# can't intercept libc.
#
# Remember to add any libraries mentioned here to the BUILD_BYPRODUCTS of the
# external compiler-rt project above.
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_libraries(
    ${PROJECT_NAME} -Wl,-whole-archive
    ${BINARY_DIR}/${LIBFUZZER_STATIC_LIB_PATH} -Wl,-no-whole-archive)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  target_link_libraries(
    ${PROJECT_NAME} -Wl,-all_load ${BINARY_DIR}/${LIBFUZZER_STATIC_LIB_PATH})
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  # Force MSVC to do an MT build, suggested by cmake-js
  cmake_policy(SET CMP0091 NEW)
  target_link_libraries(
    ${PROJECT_NAME}
    "$<LINK_LIBRARY:WHOLE_ARCHIVE,${BINARY_DIR}/${LIBFUZZER_STATIC_LIB_PATH}>")
endif()


# <--- NEW SECTION START: Add the fuzz_target executable
# Add the fuzz_target executable
add_executable(fuzz_target fuzz_target.cpp)

# Ensure compiler-rt is built before trying to link against its products
add_dependencies(fuzz_target compiler-rt)

# Add fuzzer-specific compilation and linking flags
# Use sanitizers (fuzzer, address, undefined) for effective fuzzing
target_compile_options(fuzz_target PRIVATE -fsanitize=fuzzer,address,undefined)
target_link_options(fuzz_target PRIVATE -fsanitize=fuzzer,address,undefined)

# Add include directories for fuzz_target
# This might be needed if fuzz_target.cpp uses headers from your main project
# or from the fuzzer runtime itself (e.g., <fuzzer/FuzzerDefs.h>)
target_include_directories(fuzz_target PRIVATE
                           . # For headers in the current directory
                           ${SOURCE_DIR}/compiler-rt/lib # For fuzzer headers
                           ${CMAKE_JS_INC}) # If fuzz_target needs Node.js API headers (optional, only if needed)

# Link libfuzzer (with main) to the fuzz_target executable
# Use platform-specific linking flags for whole-archive linking
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  target_link_libraries(
    fuzz_target -Wl,-whole-archive
    ${BINARY_DIR}/${FUZZ_TARGET_LIBFUZZER_STATIC_LIB_PATH} -Wl,-no-whole-archive)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
  target_link_libraries(
    fuzz_target -Wl,-all_load ${BINARY_DIR}/${FUZZ_TARGET_LIBFUZZER_STATIC_LIB_PATH})
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  target_link_libraries(
    fuzz_target
    "$<LINK_LIBRARY:WHOLE_ARCHIVE,${BINARY_DIR}/${FUZZ_TARGET_LIBFUZZER_STATIC_LIB_PATH}>")
endif()

# Optional: Add a custom target to easily run the fuzzer
add_custom_target(run_fuzz_target
    COMMAND $<TARGET_FILE:fuzz_target>
    DEPENDS fuzz_target
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}" # Or a specific directory for corpus/dictionary
    COMMENT "Running fuzz_target with default options. You can pass arguments to the fuzzer executable directly (e.g., --target=run_fuzz_target -- -max_len=100 -runs=0 corpus_dir)")
# <--- NEW SECTION END
