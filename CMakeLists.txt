cmake_minimum_required(VERSION 3.10)
project(SecureChat)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(OpenSSL REQUIRED)

# Include directories for header-only libraries
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Server executable (using server_fixed.cpp with POSIX sockets)
add_executable(server server.cpp)
target_link_libraries(server
    ${OPENSSL_LIBRARIES}
    pthread
)
target_include_directories(server PRIVATE
    ${OPENSSL_INCLUDE_DIR}
)

# Client executable
add_executable(client client.cpp)
target_link_libraries(client
    ${OPENSSL_LIBRARIES}
    pthread
)
target_include_directories(client PRIVATE
    ${OPENSSL_INCLUDE_DIR}
) 