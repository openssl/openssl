#!/usr/bin/env python3
"""
OpenSSL Conan Package Recipe
Minimal implementation for upstream integration
"""

from conan import ConanFile
from conan.errors import ConanInvalidConfiguration


class OpenSSLConan(ConanFile):
    name = "openssl"
    version = "3.3.0"
    
    # Package metadata
    description = "OpenSSL cryptographic library"
    homepage = "https://www.openssl.org"
    url = "https://github.com/openssl/openssl"
    license = "Apache-2.0"
    topics = ("openssl", "crypto", "ssl", "tls")
    
    # Package configuration
    settings = "os", "compiler", "build_type", "arch"
    options = {
        "shared": [True, False],
        "fPIC": [True, False],
    }
    default_options = {
        "shared": True,
        "fPIC": True,
    }
    
    def configure(self):
        """Configure package options"""
        # Static builds need fPIC
        if not self.options.shared:
            self.options.fPIC = True
    
    def validate(self):
        """Validate configuration"""
        # Basic validation - can be extended as needed
        pass
    
    def source(self):
        """Get source code"""
        # Source is already available in the repository
        pass
    
    def build(self):
        """Build OpenSSL"""
        # Use OpenSSL's native build system
        # This is a placeholder for the actual build integration
        self.output.info("Building OpenSSL using native build system")
    
    def package(self):
        """Package OpenSSL"""
        # Package the built OpenSSL libraries and headers
        # This is a placeholder for the actual packaging logic
        self.output.info("Packaging OpenSSL")
    
    def package_info(self):
        """Package info for OpenSSL"""
        # Libraries
        self.cpp_info.libs = ["ssl", "crypto"]
        
        # Paths
        self.cpp_info.bindirs = ["bin"]
        self.cpp_info.includedirs = ["include"]
        self.cpp_info.libdirs = ["lib"]
