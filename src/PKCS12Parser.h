/*
 * PKCS12Parser.h
 *
 *  Created on: 12/06/2025
 *      Author: marcus
 */

#ifndef SRC_PKCS12PARSER_H_
#define SRC_PKCS12PARSER_H_

#include <memory>
#include <string>

#include <openssl/ssl.h>

class PKCS12Parser {
public:
    PKCS12Parser();
    PKCS12Parser(const std::string &pkcs12_file_path);
    PKCS12Parser(const std::string &pkcs12_file_path,
            const std::string &password);
    virtual ~PKCS12Parser();
    void set_pkcs12_file_path(const std::string &pkcs12_file_path) {
        pkcs12_file_path_ = pkcs12_file_path;
    }
    void set_password(const std::string &password) {
        password_ = password;
    }
    void parse();
    X509* get_certificate() {
        return certificate_.release();
    }
    EVP_PKEY* get_private_key() {
        return private_key_.release();
    }
private:
    std::string pkcs12_file_path_;
    std::string password_;
    std::unique_ptr<X509, void(*)(X509*)> certificate_;
    std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> private_key_;
};

#endif /* SRC_PKCS12PARSER_H_ */
