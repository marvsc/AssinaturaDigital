
#include "PKCS12Parser.h"

#include "../include/OpenSSLUtils.h"

#include <cstdio>
#include <cerrno>
#include <cstring>
#include <stdexcept>

#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <Poco/Logger.h>

Data::POCO::PKCS12POCO PKCS12Parser::parse() const {
    // Abre o arquivo e define o deleter (fclose)
    std::unique_ptr<std::FILE, decltype(&std::fclose)> file(std::fopen(pkcs12_file_path_.c_str(), "rb"), std::fclose);
    if (file.get() == NULL) {
        throw std::runtime_error(
                std::string("Erro abrindo arquivo ").append(
                        pkcs12_file_path_).append(": [").append(
                        std::to_string(errno)).append("] - ").append(
                        std::strerror(errno)));
    }

    // Carrega o conteúdo do arquivo PKCS 12 e define o deleter (PKCS12_free)
    std::unique_ptr<PKCS12, decltype(&PKCS12_free)> pkcs12(d2i_PKCS12_fp(file.get(), NULL), PKCS12_free);
    if (pkcs12.get() == NULL) {
        OpenSSLUtils::openssl_error_handling("Erro criando PKCS12");
    }
    EVP_PKEY *private_key = nullptr;
    X509 *certificate = nullptr;
    STACK_OF(X509) *_certificate_authority = nullptr;
    if (!PKCS12_parse(pkcs12.get(), password_.c_str(), &private_key,
            &certificate, NULL)) {
        OpenSSLUtils::openssl_error_handling("Erro de parse");
    }

    // Instancia o poco com o certificado e com a chave primária
    Data::POCO::PKCS12POCO result(std::shared_ptr<X509>(certificate, X509_free), std::shared_ptr<EVP_PKEY>(private_key, EVP_PKEY_free));
    return result;
}

