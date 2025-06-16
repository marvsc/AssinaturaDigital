from conan import ConanFile
from conan.tools.cmake import CMakeToolchain, CMake, cmake_layout, CMakeDeps


class assinaturadigitalRecipe(ConanFile):
    name = "assinaturadigital"
    version = "0.1"
    package_type = "application"

    # Optional metadata
    license = ""
    author = "Marcus Chaves"
    url = ""
    description = "<Description of assinaturadigital package here>"
    topics = ("", "", "")

    # Binary configuration
    settings = "os", "compiler", "build_type", "arch"

    # Sources are located in the same place as this recipe, copy them to the recipe
    exports_sources = "CMakeLists.txt", "src/*"

    def requirements(self):
        self.requires("openssl/3.5.0")

    def layout(self):
        cmake_layout(self)

    def generate(self):
        deps = CMakeDeps(self)
        deps.generate()
        tc = CMakeToolchain(self)
        tc.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        cmake = CMake(self)
        cmake.install()

    

    
