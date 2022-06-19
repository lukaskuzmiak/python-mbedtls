# SPDX-License-Identifier: MIT
# Copyright (c) 2022, Lukas Kuzmiak

"""Declarations for `mbedtls/ecjpake.h`."""

cimport mbedtls._md as _md
cimport mbedtls.pk as _pk

cdef extern from "mbedtls/ecjpake.h" nogil:
    cdef struct mbedtls_ecjpake_context:
        pass

    ctypedef enum mbedtls_ecjpake_role:
        MBEDTLS_ECJPAKE_CLIENT = 0
        MBEDTLS_ECJPAKE_SERVER

    void mbedtls_ecjpake_init(mbedtls_ecjpake_context * ctx)
    void mbedtls_ecjpake_free(mbedtls_ecjpake_context * ctx)

    int mbedtls_ecjpake_setup(mbedtls_ecjpake_context * ctx, mbedtls_ecjpake_role role, _md.mbedtls_md_type_t hash,
                              _pk.mbedtls_ecp_group_id curve, unsigned char * secret, size_t len)

    int mbedtls_ecjpake_check(mbedtls_ecjpake_context * ctx)

    int mbedtls_ecjpake_write_round_one(mbedtls_ecjpake_context * ctx, unsigned char * buf, size_t len, size_t * olen,
                                        int (*f_rng)(void *, unsigned char *, size_t), void * p_rng)

    int mbedtls_ecjpake_read_round_one(mbedtls_ecjpake_context * ctx, unsigned char * buf, size_t len)

    int mbedtls_ecjpake_write_round_two(mbedtls_ecjpake_context * ctx, unsigned char * buf, size_t len, size_t * olen,
                                        int (*f_rng)(void *, unsigned char *, size_t), void * p_rng)

    int mbedtls_ecjpake_read_round_two(mbedtls_ecjpake_context * ctx, unsigned char * buf, size_t len)

    int mbedtls_ecjpake_derive_secret(mbedtls_ecjpake_context * ctx, unsigned char * buf, size_t len, size_t * olen,
                                      int (*f_rng)(void *, unsigned char *, size_t), void * p_rng)

    int mbedtls_ecjpake_self_test(int verbose)

cdef class ECJPake:
    cdef mbedtls_ecjpake_context _ctx
    cdef int _max_buffer_size
