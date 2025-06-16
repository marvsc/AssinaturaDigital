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

auto certificate_deleter = [](X509 *_certificate) {
    X509_free(_certificate);
    _certificate = nullptr;
};

auto private_key_deleter = [](EVP_PKEY *_private_key) {
    EVP_PKEY_free(_private_key);
    _private_key = nullptr;
};

PKCS12Parser::PKCS12Parser() :
        pkcs12_file_path_(""), password_(""), certificate_(nullptr,
                certificate_deleter), private_key_(nullptr, private_key_deleter) {
}

PKCS12Parser::PKCS12Parser(const std::string &pkcs12_file_path) :
        pkcs12_file_path_(pkcs12_file_path), password_(""), certificate_(
                nullptr, certificate_deleter), private_key_(nullptr,
                private_key_deleter) {
}

PKCS12Parser::PKCS12Parser(const std::string &pkcs12_file_path,
        const std::string &password) :
        pkcs12_file_path_(pkcs12_file_path), password_(password), certificate_(
                nullptr, certificate_deleter), private_key_(nullptr,
                private_key_deleter) {
}

PKCS12Parser::~PKCS12Parser() {
    if (private_key_.get() != NULL) {
        private_key_.reset();
    }
    if (certificate_.get() != NULL) {
        certificate_.reset();
    }
}

void PKCS12Parser::parse() {
    std::unique_ptr<PKCS12, void(*)(PKCS12*)> pkcs12(nullptr, [](PKCS12 *_pkcs12) {
        PKCS12_free(_pkcs12);
        _pkcs12 = nullptr;
    });
    std::unique_ptr<STACK_OF(X509), void(*)(STACK_OF(X509)*)> certificate_authority(
            nullptr, [](STACK_OF(X509) *_certificate_authority) {
                sk_X509_pop_free(_certificate_authority, X509_free);
                _certificate_authority = nullptr;
            });
    auto file_deleter = [this](std::FILE *_file) {
        if (std::fclose(_file) == EOF) {
            throw std::runtime_error(
                    std::string("Erro fechando arquivo ").append(
                            pkcs12_file_path_).append(": [").append(
                            std::to_string(errno)).append("] - ").append(
                            std::strerror(errno)));
        }
    };
    std::unique_ptr<std::FILE, decltype(file_deleter)> file(nullptr,
            file_deleter);
    auto clean = [&]() {
        pkcs12.reset();
        certificate_authority.reset();
        file.reset();
    };
    auto openssl_error = [](const char *const prefix) {
        unsigned long error = ERR_get_error();
        std::string str_prefix(prefix);
        throw std::runtime_error(
                str_prefix.append(std::to_string(error)).append("] - ").append(
                        ERR_error_string(error, NULL)));
    };
    try {
        file.reset(std::fopen(pkcs12_file_path_.c_str(), "rb"));
        if (file.get() == NULL) {
            throw std::runtime_error(
                    std::string("Erro abrindo arquivo ").append(
                            pkcs12_file_path_).append(": [").append(
                            std::to_string(errno)).append("] - ").append(
                            std::strerror(errno)));
        }
        pkcs12.reset(d2i_PKCS12_fp(file.get(), NULL));
        if (pkcs12.get() == NULL) {
            openssl_error("Erro criando PKCS12: [");
        }
        EVP_PKEY *private_key = nullptr;
        X509 *certificate = nullptr;
        STACK_OF(X509) *_certificate_authority = nullptr;
        if (!PKCS12_parse(pkcs12.get(), password_.c_str(), &private_key,
                &certificate, &_certificate_authority)) {
            openssl_error("Erro de parse: [");
        }
        private_key_.reset(private_key);
        certificate_.reset(certificate);
        certificate_authority.reset(_certificate_authority);
    } catch (...) {
        clean();
        throw;
    }
    clean();
}

