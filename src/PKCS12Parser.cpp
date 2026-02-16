
#include "PKCS12Parser.h"

#include "../include/Data/POCO/PKCS12POCO.h"

#include <cstdio>
#include <cerrno>
#include <cstring>
#include <stdexcept>

#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <Poco/Logger.h>

/*
 * @brief Função estática com escopo de arquivo para ser usada como callback de erros
 *          do openssl.
 *
 * @param[in] str Ponteiro com a mensagem de erro do openssl.
 * @param[in] len Tamanho da mensagem de erro passada pelo openssl.
 * @param[out] u Ponteiro com o prefixo da mensagem de erro para que a mensagem passada
 *                  pelo openssl seja concatenada a ela.
 *
 * @return 0 para o processamento de erro, 1 continua processando erros da openssl.
 */
static int openssl_error_callback(const char* str, std::size_t len, void* u) {
    std::string* buffer = static_cast<std::string*>(u);

    // Cada erro entre colchetes e separados por vírgula
    buffer->append(buffer->back() == ']' ? ", [" : ": [").append(str).append("]");
    return 1;
}

void PKCS12Parser::openssl_error_handling(const char* prefix) const {
    std::string error_buffer(prefix);
    ERR_print_errors_cb(openssl_error_callback, (void*) &error_buffer);
    throw std::runtime_error(error_buffer.c_str());
}

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
        openssl_error_handling("Erro criando PKCS12");
    }
    EVP_PKEY *private_key = nullptr;
    X509 *certificate = nullptr;
    STACK_OF(X509) *_certificate_authority = nullptr;
    if (!PKCS12_parse(pkcs12.get(), password_.c_str(), &private_key,
            &certificate, NULL)) {
        openssl_error_handling("Erro de parse");
    }

    // Instancia o poco com o certificado e com a chave primária
    Data::POCO::PKCS12POCO result(std::shared_ptr<X509>(certificate, X509_free), std::shared_ptr<EVP_PKEY>(private_key, EVP_PKEY_free));
    return result;
}

