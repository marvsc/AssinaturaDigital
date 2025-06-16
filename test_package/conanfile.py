import os
from conan import ConanFile
from conan.tools.build import can_run


class assinaturadigitalTestConan(ConanFile):
    settings = "os", "compiler", "build_type", "arch"

    def requirements(self):
        self.requires(self.tested_reference_str)

    def test(self):
        if can_run(self):
            self.run("assinaturadigital -x resources/pkcs12/certificado_teste_hub.pfx -p bry123456 -f resources/arquivos/doc.txt -o resources/arquivos/signature.p7s", env="conanrun")
