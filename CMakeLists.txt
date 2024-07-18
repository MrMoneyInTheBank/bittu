cmake_minimum_required(VERSION 3.13)

project(bittorrent-starter-cpp)

# Specify the C++ standard
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# Add CPR
FetchContent_Declare(cpr
        GIT_REPOSITORY https://github.com/libcpr/cpr.git
        GIT_TAG 3b15fa82ea74739b574d705fea44959b58142eb8
)
FetchContent_MakeAvailable(cpr)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

file(GLOB_RECURSE SOURCE_FILES "src/*.cpp")

# Add executable target
add_executable(bittorrent ${SOURCE_FILES}
        src/headers/bittu.hpp
        src/bittu.cpp
)

# Add include directories
target_include_directories(bittorrent PRIVATE
        "${CMAKE_SOURCE_DIR}/src"
        "${CMAKE_SOURCE_DIR}/lib/nlohmann"
        ${OPENSSL_INCLUDE_DIR}
)

# Link libraries
target_link_libraries(bittorrent PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        cpr::cpr
)
