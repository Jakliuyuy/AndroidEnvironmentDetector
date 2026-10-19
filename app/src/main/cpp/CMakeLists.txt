cmake_minimum_required(VERSION 3.22.1)

project("security_engine" CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -O2 -fvisibility=hidden -fvisibility-inlines-hidden -fPIC")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -O2 -fvisibility=hidden -fPIC")

include_directories(include)

add_library(
    security_engine
    SHARED
    src/security_engine_jni.cpp
    src/syscall_helper.cpp
    src/native_maps.cpp
    src/native_mounts.cpp
    src/native_status.cpp
    src/native_props.cpp
)

find_library(log-lib log)

target_link_libraries(
    security_engine
    ${log-lib}
)
