
#include "../include/OpenSSLUtils.h"

#include <string>

#include <openssl/err.h>

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

void OpenSSLUtils::openssl_error_handling(const char* prefix) {
    std::string error_buffer(prefix);
    ERR_print_errors_cb(openssl_error_callback, (void*) &error_buffer);
    throw std::runtime_error(error_buffer.c_str());
}
