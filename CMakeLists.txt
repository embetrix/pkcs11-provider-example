cmake_minimum_required(VERSION 3.10)

# Set the project name
project(pkcs11-provider-example)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Add the executable
add_executable(pkcs11-provider-example pkcs11-provider-example.c)

# Link the libraries
target_link_libraries(pkcs11-provider-example ${OPENSSL_LIBRARIES})
target_compile_options(pkcs11-provider-example PUBLIC -Wformat -Wformat-security -Wconversion -Wsign-conversion -pedantic -Werror)

# Specify the install rules
install(TARGETS pkcs11-provider-example DESTINATION bin)

# Enable testing
enable_testing()
add_test(NAME pkcs11-provider-example COMMAND ./pkcs11-provider-example_test.sh)
