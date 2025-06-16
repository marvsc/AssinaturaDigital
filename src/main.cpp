#include "PKCS12Parser.h"
#include "CMSSigner.h"

#include <unistd.h>

#include <string>

int main(const int argc, char *const argv[]) {
    int opt;
    std::string pkcs12_file("");
    std::string password("");
    std::string signature_file("");
    std::string file("");
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
        PKCS12Parser parser(pkcs12_file, password);
        parser.parse();
        CMSSigner signer(file, parser.get_certificate(), parser.get_private_key());
        signer.assign(signature_file);
    } catch (std::exception& e) {
        std::printf("Erro de execução: %s\n", e.what());
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
