/*
 * PKCS12Parser.h
 *
 *  Created on: 12/06/2025
 *      Author: marcus
 */

#ifndef INCLUDE_PKCS12PARSER_H_
#define INCLUDE_PKCS12PARSER_H_

#include <memory>
#include <string>

#include <openssl/ssl.h>

class PKCS12Parser {
public:
    PKCS12Parser() : pkcs12_file_path_(""), password_("") {}
    PKCS12Parser(const std::string &pkcs12_file_path) : pkcs12_file_path_(pkcs12_file_path), password_("") {}
    PKCS12Parser(const std::string &pkcs12_file_path,
            const std::string &password) : pkcs12_file_path_(pkcs12_file_path), password_(password) {}
    virtual ~PKCS12Parser() {}
    void set_pkcs12_file_path(const std::string &pkcs12_file_path) {
        pkcs12_file_path_ = pkcs12_file_path;
    }
    void set_password(const std::string &password) {
        password_ = password;
    }
    void parse();
    std::shared_ptr<X509> get_certificate() {
        return certificate_;
    }
    std::shared_ptr<EVP_PKEY> get_private_key() {
        return private_key_;
    }
private:
    std::string pkcs12_file_path_;
    std::string password_;
    std::shared_ptr<X509> certificate_;
    std::shared_ptr<EVP_PKEY> private_key_;

    void openssl_error_handling(const char* prefix) const;
};

#endif /* INCLUDE_PKCS12PARSER_H_ */
