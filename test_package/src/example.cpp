/*
 * @file example.cpp
 * @brief Arquivo de exemplo de implementação
 * @author Marcus Chaves
 * @date 2026-01-27
 */
#include "CMSSigner.h"
#include "PKCS12Parser.h"

#include "Data/POCO/PKCS12POCO.h"

#include <string>
#include <unistd.h>

int main(const int argc, char *const argv[]) {
    int opt;
    std::string pkcs12_file("");
    std::string password("");
    std::string signature_file("");
    std::string file("");

    // Parse de opções passadas por parâmetro
    while ((opt = getopt(argc, argv, "f:p:o:x:")) != -1) {
        switch (opt) {
        case 'x':
            pkcs12_file = optarg;
            break;
        case 'p':
            password = optarg;
            break;
        case 'o':
            signature_file = optarg;
            break;
        case 'f':
            file = optarg;
            break;
        case '?':
            std::printf("Opção inválida: %c\n", opt);
            break;
        default:
            std::printf("Erro no parser: %c\n", opt);
            break;
        }
    }
    if (optind < argc) {
        for (int i = optind; i < argc; i++) {
            std::printf("Argumento inválido: %s\n", argv[i]);
        }
    }
    if (pkcs12_file.empty()) {
        std::printf("Arquivo PKCS12 inválido\n");
        return EXIT_FAILURE;
    }
    if (password.empty()) {
        std::printf("Senha inválida\n");
        return EXIT_FAILURE;
    }
    if (signature_file.empty()) {
        std::printf("Arquivo de assinatura inválido\n");
        return EXIT_FAILURE;
    }
    if (file.empty()) {
        std::printf("Arquivo inválido\n");
        return EXIT_FAILURE;
    }
    try {
        // Instanciando o parser de PKCS 12 baseado em um arquivo PKCS 12 e uma senha
        //  para acesso aos dados
        PKCS12Parser parser(pkcs12_file, password);
        Data::POCO::PKCS12POCO pkcs12Poco = parser.parse();
        CMSSigner signer(file, pkcs12Poco.certificate, pkcs12Poco.private_key);

        // Gerando arquivo de assinatura
        signer.assign(signature_file);
    } catch (std::exception& e) {
        std::printf("Erro de execução: %s\n", e.what());
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
