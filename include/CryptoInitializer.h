/*
 * @file CryptoInitializer.h
 * @brief Declaração da classe CryptoInitializer
 * @author Marcus Chaves
 * @date 2026-07-02
 */

#ifndef INCLUDE_CRYPTOINITIALIZER_H_
#define INCLUDE_CRYPTOINITIALIZER_H_

/*
 * @class CryptoInitializer
 * @brief Classe Mayer's Singleton com RAII para inicializar a biblioteca de criptografia da Poco.
 */
class CryptoInitializer {
public:

    /*
     * @brief Impede a cópia da classe.
     */
    CryptoInitializer(const CryptoInitializer&) = delete;

    /*
     * @brief Impede a atribuição da classe.
     */
    CryptoInitializer& operator=(const CryptoInitializer&) = delete;

    /*
     * @brief Inicializa a biblioteca de criptografia.
     */
    static void ensure();
private:

    /*
     * @brief Constrói a classe e inicializa a biblioteca de criptografia.
     */
    CryptoInitializer();

    /*
     * @brief Não permite a destruição da classe fora do escopo.
     */
    virtual ~CryptoInitializer() = default;
};

#endif /* INCLUDE_CRYPTOINITIALIZER_H_ */
