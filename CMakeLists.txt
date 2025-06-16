cmake_minimum_required(VERSION 3.15)
project(assinaturadigital CXX)

find_package(OpenSSL REQUIRED)

add_executable(assinaturadigital src/PKCS12Parser.cpp src/CMSSigner.cpp src/main.cpp)

target_link_libraries(assinaturadigital OpenSSL::SSL OpenSSL::Crypto)

install(TARGETS assinaturadigital DESTINATION "."
        RUNTIME DESTINATION bin
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
        )
