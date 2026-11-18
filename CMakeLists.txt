cmake_minimum_required(VERSION 3.20)
project(xelis-v3-miner LANGUAGES C CXX)

option(ENABLE_CUDA "Enable NVIDIA CUDA GPU mining" ON)

set(CMAKE_C_STANDARD 99)
if(UNIX)
    add_compile_definitions(_POSIX_C_SOURCE=200809L)
endif()
set(CMAKE_CXX_STANDARD 17)

if(MSVC)
    add_compile_options($<$<COMPILE_LANGUAGE:C>:/utf-8> $<$<COMPILE_LANGUAGE:CXX>:/utf-8>)
endif()

if(WIN32 AND NOT DEFINED OPENSSL_ROOT_DIR)
    if(EXISTS "C:/Program Files/OpenSSL-Win64")
        set(OPENSSL_ROOT_DIR "C:/Program Files/OpenSSL-Win64")
    elseif(EXISTS "C:/OpenSSL-Win64")
        set(OPENSSL_ROOT_DIR "C:/OpenSSL-Win64")
    endif()
endif()

find_package(OpenSSL QUIET)
if(NOT OpenSSL_FOUND AND WIN32 AND DEFINED OPENSSL_ROOT_DIR)
    find_path(OPENSSL_INCLUDE_DIR openssl/ssl.h HINTS "${OPENSSL_ROOT_DIR}/include")
    find_library(OPENSSL_SSL_LIBRARY NAMES libssl ssl libssl_static HINTS "${OPENSSL_ROOT_DIR}/lib" "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD" "${OPENSSL_ROOT_DIR}/lib/VC/x64/MT")
    find_library(OPENSSL_CRYPTO_LIBRARY NAMES libcrypto crypto libcrypto_static HINTS "${OPENSSL_ROOT_DIR}/lib" "${OPENSSL_ROOT_DIR}/lib/VC/x64/MD" "${OPENSSL_ROOT_DIR}/lib/VC/x64/MT")
    if(OPENSSL_INCLUDE_DIR AND OPENSSL_SSL_LIBRARY AND OPENSSL_CRYPTO_LIBRARY)
        add_library(OpenSSL::Crypto UNKNOWN IMPORTED)
        set_target_properties(OpenSSL::Crypto PROPERTIES IMPORTED_LOCATION "${OPENSSL_CRYPTO_LIBRARY}" INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}")
        add_library(OpenSSL::SSL UNKNOWN IMPORTED)
        set_target_properties(OpenSSL::SSL PROPERTIES IMPORTED_LOCATION "${OPENSSL_SSL_LIBRARY}" INTERFACE_INCLUDE_DIRECTORIES "${OPENSSL_INCLUDE_DIR}")
        set(OpenSSL_FOUND TRUE)
    endif()
endif()
if(NOT OpenSSL_FOUND)
    find_package(OpenSSL REQUIRED)
endif()

set(CORE_SOURCES
    src/miner_common.c
    src/miner_net.c
    src/xelis_hash_v3_ref.c
    src/xelis_v3_oracle.c
)

if(ENABLE_CUDA)
    enable_language(CUDA)
    set(CMAKE_CUDA_STANDARD 17)

    # Target NVIDIA RTX 30/40/50 + Datacenter architectures:
    # CUDA 13.0+ dropped Pascal (sm_60) -> target sm_75, sm_80/86, sm_89, sm_90a, sm_100a, sm_120a
    if(CMAKE_CUDA_COMPILER_VERSION VERSION_GREATER_EQUAL "13.0")
        set(CMAKE_CUDA_ARCHITECTURES "75;80;86;89;90a;100a;120a")
    elseif(CMAKE_CUDA_COMPILER_VERSION VERSION_GREATER_EQUAL "12.8")
        set(CMAKE_CUDA_ARCHITECTURES "60;75;80;86;89;90a;100a;120a")
    elseif(CMAKE_CUDA_COMPILER_VERSION VERSION_GREATER_EQUAL "12.0")
        set(CMAKE_CUDA_ARCHITECTURES "60;75;80;86;89;90a")
    else()
        set(CMAKE_CUDA_ARCHITECTURES "60;75;80;86;89")
    endif()

    add_library(xelis_v3_oracle STATIC ${CORE_SOURCES} src/xelis_v3_kernel.cu)
    target_compile_definitions(xelis_v3_oracle PUBLIC USE_CUDA)
    target_compile_options(xelis_v3_oracle PRIVATE
        $<$<COMPILE_LANGUAGE:CUDA>:-O3 --use_fast_math -Xptxas -v $<$<CXX_COMPILER_ID:MSVC>:-Xcompiler=/utf-8>>
    )
    set_target_properties(xelis_v3_oracle PROPERTIES CUDA_SEPARABLE_COMPILATION OFF)
else()
    add_library(xelis_v3_oracle STATIC ${CORE_SOURCES})
endif()

target_include_directories(xelis_v3_oracle PUBLIC include ${OPENSSL_INCLUDE_DIR})
target_link_libraries(xelis_v3_oracle PUBLIC OpenSSL::SSL OpenSSL::Crypto)
if(WIN32)
    target_link_libraries(xelis_v3_oracle PUBLIC ws2_32 crypt32)
else()
    target_link_libraries(xelis_v3_oracle PUBLIC m pthread)
endif()

add_executable(xelis-v3-miner src/main.c)
target_link_libraries(xelis-v3-miner PRIVATE xelis_v3_oracle)

add_executable(xelis-v3-hashgen src/hashgen_main.c)
target_link_libraries(xelis-v3-hashgen PRIVATE xelis_v3_oracle)
