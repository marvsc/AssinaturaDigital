cmake_minimum_required(VERSION 3.15)
project(assinaturadigital CXX)

find_package(OpenSSL CONFIG REQUIRED)
find_package(Poco CONFIG REQUIRED)

add_library(assinaturadigital src/PKCS12Parser.cpp src/CMSSigner.cpp src/OpenSSLUtils.cpp)
target_include_directories(assinaturadigital PUBLIC include)

target_link_libraries(assinaturadigital PRIVATE openssl::openssl)
target_link_libraries(assinaturadigital PRIVATE Poco::Poco)

set(AT_PUBLIC_HEADERS
"include/CMSSigner.h"
"include/PKCS12Parser.h"
"include/OpenSSLUtils.h")
set_target_properties(assinaturadigital PROPERTIES PUBLIC_HEADER "${AT_PUBLIC_HEADERS}")
install(TARGETS assinaturadigital)

set_target_properties(assinaturadigital PROPERTIES PUBLIC_HEADER "include/Data/POCO/PKCS12POCO.h")
install(TARGETS assinaturadigital PUBLIC_HEADER DESTINATION "include/Data/POCO")
