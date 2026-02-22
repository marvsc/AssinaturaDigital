# 🚀 AssinaturaDigital

> Biblioteca para realizar assinatura digital de arquivo.

## 📋 Tabela de Conteúdos
- [Sobre](#sobre)
- [Funcionalidades](#funcionalidades)
- [Pré-requisitos](#pré-requisitos)
- [Instalação](#instalação)
- [Como Usar](#como-usar)
- [Contribuição](#contribuição)
- [Licença](#licença)

## 📖 Sobre
Faz o parse de arquivos PKCS 12 armazenando chave privada e certificado em memória, faz assinatura digital de arquivo utilizando algoritmo Cryptographic Message Syntax (CMS) incluindo o conteúdo da mensagem dentro da estrutura da assinatura (attached) e ainda expõe algumas utilidades para criptografia como por exemplo decodificação base 64 e decodificação de string em algoritmo AES com chave de 256 bits e modo Cipher Block Chaining (CBC).

## ✨ Funcionalidades
- [ ] Decodificação de arquivo PKCS 12 em memória
- [ ] Assinatura digital de arquivo em algoritmo CMS attached em disco
- [ ] Assinatura digital de arquivo em algoritmo CMS attached em memória (base 64)
- [ ] Decodificação de string em base 64
- [ ] Decodificação de string em base 64 e algoritmo AES-256-CBC

## 🛠️ Pré-requisitos
--- CONSTRUÇÃO

## 🚀 Instalação
--- CONSTRUÇÃO


Realiza a assinatura digital do arquivo /test_package/resources/arquivos/doc.txt gerando a assinatura no arquivo /test_package/resources/arquivos/sinature.p7s.
A assinatura é feita utilizando a chave privada e o certificado contidos no arquivo PKCS12 /test_package/resources/pkcs12/certificado_teste_hub.pfx.