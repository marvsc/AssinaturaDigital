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

    /*
     * @brief Decifra string em base 64 criptografada com algoritmo AES utilizando chave de 256
     *          bits no modo Cipher Block Chaining.
     *
     * @param[in] cipher_text String a ser decifrada.
     * @param[in] key Chave simétrica.
     * @param[in] initialization_vector Vetor de inicialização.
     *
     * @return String decifrada.
     */
    static std::string decrypt_aes_256_cbc(const std::string& cipher_text,
            const std::string& key, const unsigned char* initialization_vector);

    /*
     * @brief Decodifica string em base 64.
     *
     * @param[in] input String em base 64.
     *
     * @return String decodificada.
     */
    static std::string base64_decode(const std::string& input);
};

#endif /* INCLUDE_OPENSSLUTILS_H_ */
