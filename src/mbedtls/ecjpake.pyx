# SPDX-License-Identifier: MIT
# Copyright (c) 2022, Lukas Kuzmiak

"""EC J-PAKE wrapper"""

from libc.stdlib cimport free, malloc

cimport mbedtls._random as _rnd

import mbedtls.exceptions as _exc

cdef _rnd.Random __rng = _rnd.default_rng()

cpdef enum ECJPakeRole:
    CLIENT = MBEDTLS_ECJPAKE_CLIENT
    SERVER = MBEDTLS_ECJPAKE_SERVER

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
