/*
 * @file OpenSSLUtils.h
 * @brief Declaração da classe OpenSSLUtils e métodos.
 * @author Marcus Chaves
 * @date 2026-01-27
 */

#ifndef INCLUDE_OPENSSLUTILS_H_
#define INCLUDE_OPENSSLUTILS_H_

#include <stdexcept>

/*
 * @class OpenSSLUtils
 * @brief Utilidades para o OpenSSL.
 */
class OpenSSLUtils {
public:
    /*
     * @brief Obtém a descrição completa dos erros gerados pelas
     *          operações do openssl e disparar uma exceção.
     *
     * @param[in] prefix Prefixo da mensagem de erro que será disparada na exceção.
     */
    static void openssl_error_handling(const char* prefix);
};

#endif /* INCLUDE_OPENSSLUTILS_H_ */
