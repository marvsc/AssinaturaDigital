
#include "../include/OpenSSLUtils.h"

#include <string>
#include <memory>

#include <openssl/err.h>
#include <openssl/evp.h>

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

std::string OpenSSLUtils::base64_decode(const std::string& input) {
    // Instancia um buffer de base 64 e seta flag para não haver quebra de linha
    // XXX: Esse buffer é instanciado sem smart pointer e sem deleter porque será
    //      adicionado a uma cadeia de buffers.
    BIO* base64_buffer = BIO_new(BIO_f_base64());
    BIO_set_flags(base64_buffer, BIO_FLAGS_BASE64_NO_NL);

    // Instancia uma cadeia de buffers com o buffer de base 64 e o buffer da string codificada.
    std::unique_ptr<BIO, decltype(&BIO_free_all)> input_buffer(BIO_push(base64_buffer,
            BIO_new_mem_buf(reinterpret_cast<const unsigned char*>(input.c_str()), input.length())), BIO_free_all);

    // Calcula o tamanho aproximado da string decodificada que deve ser 3/4 +1 do tamanho
    // da string codificada.
    std::size_t output_buffer_length = ((input.length() * 3) / 4) + 1;
    unsigned char* output_buffer = new unsigned char[output_buffer_length];
    if (!output_buffer) {
        throw std::runtime_error("Erro alocando buffer");
    }

    // Decodifica a string em base 64.
    std::size_t output_length = BIO_read(input_buffer.get(), output_buffer, output_buffer_length);
    if (output_length < 0) {
        delete output_buffer;
        output_buffer = nullptr;
        openssl_error_handling("Erro decodificando base 64: ");
    }
    std::string output(reinterpret_cast<const char*>(output_buffer), output_length);
    return output;
}

std::string OpenSSLUtils::decrypt_aes_256_cbc(const std::string& cipher_text, const std::string& key, const unsigned char* initialization_vector) {
    std::string binary = base64_decode(cipher_text);

    // Instancia o contexto de cifra definindo o deleter
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)> context(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!context.get()) {
        openssl_error_handling("Não foi possível criar contexto para decifrar AES: ");
    }

    // Inicializa a decodificação validando chave e vetor de inicialização
    if (!EVP_DecryptInit_ex(context.get(), EVP_aes_256_cbc(), nullptr, reinterpret_cast<const unsigned char*>(key.c_str()), initialization_vector)){
        openssl_error_handling("Não foi possível inicializar o processo de decifragem AES: ");
    }

    // Declara o buffer da string decifrada calculando o tamanho aproximado
    unsigned char buffer[binary.size() + EVP_CIPHER_block_size(EVP_aes_256_cbc())];
    int buffer_length;

    // Atualiza a decodificação já definido parte do buffer da string decifrada
    if (!EVP_DecryptUpdate(context.get(), buffer, &buffer_length, reinterpret_cast<const unsigned char*>(binary.c_str()), binary.size())) {
        openssl_error_handling("Não foi possível atualizar o processo de decifragem AES: ");
    }

    // Finaliza a decodificação
    if (!EVP_DecryptFinal_ex(context.get(), buffer + buffer_length, &buffer_length)) {
        openssl_error_handling("Não foi possível finalizar o processo de decifragem AES: ");
    }
    std::string plain_text(reinterpret_cast<const char*>(buffer), buffer_length);
    return plain_text;
}
