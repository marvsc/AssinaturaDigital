/*
 * PKCS12Parser.cpp
 *
 *  Created on: 12/06/2025
 *      Author: marcus
 */

#include "PKCS12Parser.h"

#include <cstdio>
#include <cerrno>
#include <cstring>
#include <stdexcept>

#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <Poco/Logger.h>

static int openssl_error_callback(const char* str, std::size_t len, void* u) {
    std::string* buffer = static_cast<std::string*>(u);
    buffer->append(buffer->back() == ']' ? ", [" : ": [").append(str).append("]");
    return 0;
}

void PKCS12Parser::openssl_error_handling(const char* prefix) const {
    std::string error_buffer(prefix);
    ERR_print_errors_cb(openssl_error_callback, (void*) &error_buffer);
    throw std::runtime_error(error_buffer.c_str());
}

void PKCS12Parser::parse() {
    std::unique_ptr<std::FILE, int(*)(std::FILE*)> file(std::fopen(pkcs12_file_path_.c_str(), "rb"), std::fclose);
    if (file.get() == NULL) {
        throw std::runtime_error(
                std::string("Erro abrindo arquivo ").append(
                        pkcs12_file_path_).append(": [").append(
                        std::to_string(errno)).append("] - ").append(
                        std::strerror(errno)));
    }
    std::unique_ptr<PKCS12, decltype(&PKCS12_free)> pkcs12(d2i_PKCS12_fp(file.get(), NULL), PKCS12_free);
    if (pkcs12.get() == NULL) {
        openssl_error_handling("Erro criando PKCS12");
    }
    EVP_PKEY *private_key = nullptr;
    X509 *certificate = nullptr;
    STACK_OF(X509) *_certificate_authority = nullptr;
    if (!PKCS12_parse(pkcs12.get(), password_.c_str(), &private_key,
            &certificate, NULL)) {
        openssl_error_handling("Erro de parse");
    }
    private_key_.reset(private_key, EVP_PKEY_free);
    certificate_.reset(certificate, X509_free);
}

