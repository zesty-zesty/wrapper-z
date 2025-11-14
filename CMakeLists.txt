cmake_minimum_required(VERSION 3.25)

project(wrapper)
include(ExternalProject)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)

option(BUILD_MAIN "Build the 'main' binary that links device libs" ON)

set(ANDROID_NDK_PATH "$ENV{HOME}/android-ndk-r23b")
set(TOOLCHAIN "${ANDROID_NDK_PATH}/toolchains/llvm/prebuilt/linux-x86_64")

set(CMAKE_C_COMPILER "${TOOLCHAIN}/bin/aarch64-linux-android22-clang")
set(CMAKE_CXX_COMPILER "${TOOLCHAIN}/bin/aarch64-linux-android22-clang++")
set(C_COMPILER "${TOOLCHAIN}/bin/aarch64-linux-android22-clang")

set(CMDLINE_SOURCE cmdline.c)
set(HANDLE_SOURCE main.cpp)
set(CJSON_SOURCE cjson/cjson.c)
set(MAIN_SOURCE main.c)
set(WRAPPER_SOURCE wrapper.c)
set(THREAD_POOL_SOURCE thread_pool.c)

add_library(cmdline_object OBJECT ${CMDLINE_SOURCE})
add_library(handle_object OBJECT ${HANDLE_SOURCE})
add_library(cjson_object OBJECT ${CJSON_SOURCE})

if(BUILD_MAIN)
  # Resolve library directory by architecture
  set(LIB_BASE "${CMAKE_SOURCE_DIR}/rootfs/system/lib64")
  set(LIB_DIR "${LIB_BASE}")
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64)$" AND EXISTS "${LIB_BASE}/x86_64")
    set(LIB_DIR "${LIB_BASE}/x86_64")
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)$" AND EXISTS "${LIB_BASE}/arm64")
    set(LIB_DIR "${LIB_BASE}/arm64")
  endif()

  # Probe architecture of provided libs; skip building 'main' if mismatch
  set(BUILD_MAIN_LIBS_OK TRUE)
  if(EXISTS "${LIB_DIR}/libandroidappmusic.so")
    execute_process(COMMAND file "${LIB_DIR}/libandroidappmusic.so" OUTPUT_VARIABLE LIB_DESC_ANDROIDAPP)
    if( (CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64" AND NOT LIB_DESC_ANDROIDAPP MATCHES "x86-64") OR
        (CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64" AND NOT LIB_DESC_ANDROIDAPP MATCHES "aarch64|ARM") )
      message(WARNING "Library architecture mismatch: ${LIB_DESC_ANDROIDAPP}. Skipping 'main' target build.")
      set(BUILD_MAIN_LIBS_OK FALSE)
    endif()
  endif()

  if(BUILD_MAIN_LIBS_OK)
    add_executable(main ${MAIN_SOURCE} ${THREAD_POOL_SOURCE} $<TARGET_OBJECTS:cmdline_object> $<TARGET_OBJECTS:handle_object> $<TARGET_OBJECTS:cjson_object>)

    set_target_properties(main PROPERTIES 
        COMPILE_DEFINITIONS "MyRelease"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/rootfs/system/bin"
    )

    find_library(ANDROIDAPPMUSIC_LIB androidappmusic PATHS ${LIB_DIR})
    find_library(STORESERVICESCORE_LIB storeservicescore PATHS ${LIB_DIR})
    find_library(MEDIAPLATFORM_LIB mediaplatform PATHS ${LIB_DIR})
    find_library(CXX_SHARED_LIB c++_shared PATHS ${LIB_DIR} ${ANDROID_NDK_PATH}/sources/cxx-stl/llvm-libc++/libs/x86_64 ${ANDROID_NDK_PATH}/sources/cxx-stl/llvm-libc++/libs/arm64-v8a)
    find_library(CURL_SHARED_LIB curl PATHS ${LIB_DIR})
    find_library(LOG_SHARED_LIB log PATHS ${LIB_DIR})

    find_package(Threads REQUIRED)

    target_link_libraries(main
        ${CXX_SHARED_LIB}
        ${ANDROIDAPPMUSIC_LIB}
        ${STORESERVICESCORE_LIB}
        ${MEDIAPLATFORM_LIB}
        Threads::Threads
    )

    get_target_property(MAIN_COMPILE_DEFINITIONS main COMPILE_DEFINITIONS)
    if(NOT "MyRelease" IN_LIST MAIN_COMPILE_DEFINITIONS)
        target_link_libraries(main
            ${LOG_SHARED_LIB}
            ${CURL_SHARED_LIB}
        )
        set(CMAKE_C_FLAGS "-Werror -g")
        set(CMAKE_CXX_FLAGS "-Werror -g")
    else()
        set(CMAKE_C_FLAGS "-Wall -Werror")
        set(CMAKE_CXX_FLAGS "-Wall -Werror")
    endif()

    link_directories(${LIB_DIR})
  endif()
endif()

ExternalProject_Add(
    wrapper
    PREFIX ${CMAKE_BINARY_DIR}
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${C_COMPILER} -O3 -Wall -o wrapper ${WRAPPER_SOURCE} ${CMAKE_CURRENT_SOURCE_DIR}/cmdline.c
    BUILD_IN_SOURCE 1
    INSTALL_COMMAND ""
)