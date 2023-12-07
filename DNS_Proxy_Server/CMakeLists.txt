cmake_minimum_required(VERSION 3.22)
project(DNSProxy C)

set(CMAKE_C_STANDARD 17)

add_executable(DNSProxy main.c)

add_subdirectory(src)

target_link_libraries(DNSProxy PUBLIC src)

target_include_directories(DNSProxy PUBLIC
        "${PROJECT_BINARY_DIR}"
        "${PROJECT_SOURCE_DIR}/src"
)