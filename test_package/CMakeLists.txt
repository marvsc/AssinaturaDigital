cmake_minimum_required(VERSION 3.15)
project(PackageTest CXX)

find_package(assinaturadigital REQUIRED)
find_package(cppunit CONFIG REQUIRED)
find_package(Poco CONFIG REQUIRED)

add_executable(example src/example.cpp)
target_link_libraries(example assinaturadigital::assinaturadigital Poco::Poco)

add_executable(teste src/teste.cpp
                    src/UnitTests/src/CMSSignerTest.cpp)
target_link_libraries(teste assinaturadigital::assinaturadigital cppunit::cppunit Poco::Poco)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/resources/arquivos/doc.txt
${CMAKE_CURRENT_BINARY_DIR}/doc.txt
COPYONLY)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/resources/pkcs12/certificado_teste_hub.pfx
${CMAKE_CURRENT_BINARY_DIR}/certificado_teste_hub.pfx
COPYONLY)
