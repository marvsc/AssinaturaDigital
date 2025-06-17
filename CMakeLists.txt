cmake_minimum_required(VERSION 3.15)
project(assinaturadigital CXX)

find_package(OpenSSL REQUIRED)


add_library(assinaturadigital src/PKCS12Parser.cpp src/CMSSigner.cpp)
target_include_directories(assinaturadigital PUBLIC include)

target_link_libraries(assinaturadigital OpenSSL::SSL OpenSSL::Crypto)

set(AT_PUBLIC_HEADERS
"include/CMSSigner.h"
"include/PKCS12Parser.h")
set_target_properties(assinaturadigital PROPERTIES PUBLIC_HEADER "${AT_PUBLIC_HEADERS}")
install(TARGETS assinaturadigital)
