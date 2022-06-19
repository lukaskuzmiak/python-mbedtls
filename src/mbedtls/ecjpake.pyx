# SPDX-License-Identifier: MIT
# Copyright (c) 2022, Lukas Kuzmiak

"""EC J-PAKE wrapper"""

from libc.stdlib cimport free, malloc

cimport mbedtls.pk as _pk
cimport mbedtls._random as _rnd

import mbedtls.exceptions as _exc

cdef _rnd.Random __rng = _rnd.default_rng()

cpdef enum ECJPakeRole:
    CLIENT = MBEDTLS_ECJPAKE_CLIENT
    SERVER = MBEDTLS_ECJPAKE_SERVER

cpdef enum ECPGroupId:
    NONE = _pk.MBEDTLS_ECP_DP_NONE
    SECP192R1 = _pk.MBEDTLS_ECP_DP_SECP192R1
    SECP224R1 = _pk.MBEDTLS_ECP_DP_SECP224R1
    SECP256R1 = _pk.MBEDTLS_ECP_DP_SECP256R1
    SECP384R1 = _pk.MBEDTLS_ECP_DP_SECP384R1
    SECP521R1 = _pk.MBEDTLS_ECP_DP_SECP521R1
    BP256R1 = _pk.MBEDTLS_ECP_DP_BP256R1
    BP384R1 = _pk.MBEDTLS_ECP_DP_BP384R1
    BP512R1 = _pk.MBEDTLS_ECP_DP_BP512R1
    CURVE25519 = _pk.MBEDTLS_ECP_DP_CURVE25519
    SECP192K1 = _pk.MBEDTLS_ECP_DP_SECP192K1
    SECP224K1 = _pk.MBEDTLS_ECP_DP_SECP224K1
    SECP256K1 = _pk.MBEDTLS_ECP_DP_SECP256K1
    CURVE448 = _pk.MBEDTLS_ECP_DP_CURVE448

cpdef enum MDType: # this is not defined in _md.pxd so it is here
    MBEDTLS_MD_NONE = 0
    MBEDTLS_MD_MD5 = 1
    MBEDTLS_MD_SHA1 = 2
    MBEDTLS_MD_SHA224 = 3
    MBEDTLS_MD_SHA256 = 4
    MBEDTLS_MD_SHA384 = 5
    MBEDTLS_MD_SHA512 = 6
    MBEDTLS_MD_RIPEMD160 = 7

cdef class ECJPake:
    def __init__(self):
        self._max_buffer_size = 1024

    def __cinit__(self):
        mbedtls_ecjpake_init(&self._ctx)

    def __dealloc__(self):
        mbedtls_ecjpake_free(&self._ctx)

    def setup(self, role, hash, curve, const unsigned char[:] secret not None):
        if secret.size == 0:
            secret = b"\0"
        _exc.check_error(mbedtls_ecjpake_setup(&self._ctx, role, hash, curve, &secret[0], secret.size))

    def check(self):
        _exc.check_error(mbedtls_ecjpake_check(&self._ctx))

    def write_round_one(self):
        cdef size_t olen = 0
        cdef unsigned char * buffer = <unsigned char *> malloc(self._max_buffer_size)
        if not buffer:
            raise MemoryError()
        try:
            _exc.check_error(mbedtls_ecjpake_write_round_one(&self._ctx, &buffer[0], self._max_buffer_size,
                                                             &olen, &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
            assert olen != 0
            return buffer[:olen]
        finally:
            free(buffer)

    def read_round_one(self, const unsigned char[:] buffer not None):
        if buffer.size == 0:
            buffer = b"\0"
        _exc.check_error(mbedtls_ecjpake_read_round_one(&self._ctx, &buffer[0], buffer.size))

    def write_round_two(self):
        cdef size_t olen = 0
        cdef unsigned char * buffer = <unsigned char *> malloc(self._max_buffer_size)
        if not buffer:
            raise MemoryError()
        try:
            _exc.check_error(mbedtls_ecjpake_write_round_two(&self._ctx, &buffer[0], self._max_buffer_size,
                                                             &olen, &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
            assert olen != 0
            return buffer[:olen]
        finally:
            free(buffer)

    def read_round_two(self, const unsigned char[:] buffer not None):
        if buffer.size == 0:
            buffer = b"\0"
        _exc.check_error(mbedtls_ecjpake_read_round_two(&self._ctx, &buffer[0], buffer.size))

    def derive_secret(self):
        cdef size_t olen = 0
        cdef unsigned char * buffer = <unsigned char *> malloc(self._max_buffer_size)
        if not buffer:
            raise MemoryError()
        try:
            _exc.check_error(mbedtls_ecjpake_derive_secret(&self._ctx, &buffer[0], self._max_buffer_size,
                                                           &olen, &_rnd.mbedtls_ctr_drbg_random, &__rng._ctx))
            assert olen != 0
            return buffer[:olen]
        finally:
            free(buffer)

    def self_test(self, const int verbose):
        _exc.check_error(mbedtls_ecjpake_self_test(verbose))
