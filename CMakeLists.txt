cmake_minimum_required(VERSION 3.15)
project(assinaturadigital CXX)

find_package(OpenSSL CONFIG REQUIRED)
find_package(Poco CONFIG REQUIRED)

add_library(assinaturadigital src/CMSSigner.cpp src/OpenSSLUtils.cpp)
target_include_directories(assinaturadigital PUBLIC include)

target_link_libraries(assinaturadigital PRIVATE openssl::openssl Poco::Poco)

set(AT_PUBLIC_HEADERS
"include/CMSSigner.h"
"include/OpenSSLUtils.h")
set_target_properties(assinaturadigital PROPERTIES PUBLIC_HEADER "${AT_PUBLIC_HEADERS}")
install(TARGETS assinaturadigital)
