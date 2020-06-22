//
//  openssl.h
//  OpenSSL-iOS
//
//  Created by @levigroker Fri Apr 24 15:21:34 MDT 2020.
//  Copyright © 2020 @levigroker. All rights reserved.
//

#ifndef openssl_h
#define openssl_h

#ifdef __OBJC__

#import <Foundation/Foundation.h>

//! Project version number for OpenSSL-iOS.
FOUNDATION_EXPORT double OpenSSL_iOSVersionNumber;

//! Project version string for OpenSSL-iOS.
FOUNDATION_EXPORT const unsigned char OpenSSL_iOSVersionString[];

#endif

#import <CNIOOpenSSL/rc4.h>
#import <CNIOOpenSSL/rc2.h>
#import <CNIOOpenSSL/idea.h>
#import <CNIOOpenSSL/bn.h>
#import <CNIOOpenSSL/des.h>
#import <CNIOOpenSSL/des_old.h>
#import <CNIOOpenSSL/opensslconf.h>
#import <CNIOOpenSSL/md4.h>
#import <CNIOOpenSSL/md5.h>
#import <CNIOOpenSSL/mdc2.h>
#import <CNIOOpenSSL/pkcs12.h>
#import <CNIOOpenSSL/pkcs7.h>
#import <CNIOOpenSSL/pqueue.h>
#import <CNIOOpenSSL/rand.h>
#import <CNIOOpenSSL/ripemd.h>
#import <CNIOOpenSSL/rsa.h>
#import <CNIOOpenSSL/safestack.h>
#import <CNIOOpenSSL/seed.h>
#import <CNIOOpenSSL/sha.h>
#import <CNIOOpenSSL/srp.h>
#import <CNIOOpenSSL/srtp.h>
#import <CNIOOpenSSL/ssl.h>
#import <CNIOOpenSSL/ssl2.h>
#import <CNIOOpenSSL/ssl23.h>
#import <CNIOOpenSSL/ssl3.h>
#import <CNIOOpenSSL/tls1.h>
#import <CNIOOpenSSL/ts.h>
#import <CNIOOpenSSL/txt_db.h>
#import <CNIOOpenSSL/ui.h>
#import <CNIOOpenSSL/ui_compat.h>
#import <CNIOOpenSSL/whrlpool.h>
#import <CNIOOpenSSL/x509.h>
#import <CNIOOpenSSL/x509_vfy.h>
#import <CNIOOpenSSL/x509v3.h>
#import <CNIOOpenSSL/dtls1.h>
#import <CNIOOpenSSL/ecdh.h>
#import <CNIOOpenSSL/ecdsa.h>
#import <CNIOOpenSSL/engine.h>
#import <CNIOOpenSSL/ocsp.h>
#import <CNIOOpenSSL/opensslv.h>
#import <CNIOOpenSSL/ossl_typ.h>
#import <CNIOOpenSSL/pem.h>
#import <CNIOOpenSSL/pem2.h>
#import <CNIOOpenSSL/stack.h>
#import <CNIOOpenSSL/symhacks.h>
#import <CNIOOpenSSL/blowfish.h>
#import <CNIOOpenSSL/buffer.h>
#import <CNIOOpenSSL/camellia.h>
#import <CNIOOpenSSL/cast.h>
#import <CNIOOpenSSL/cmac.h>
#import <CNIOOpenSSL/aes.h>
#import <CNIOOpenSSL/asn1.h>
#import <CNIOOpenSSL/asn1_mac.h>
#import <CNIOOpenSSL/asn1t.h>
#import <CNIOOpenSSL/bio.h>
#import <CNIOOpenSSL/cms.h>
#import <CNIOOpenSSL/comp.h>
#import <CNIOOpenSSL/conf.h>
#import <CNIOOpenSSL/conf_api.h>
#import <CNIOOpenSSL/crypto.h>
#import <CNIOOpenSSL/dh.h>
#import <CNIOOpenSSL/dsa.h>
#import <CNIOOpenSSL/krb5_asn.h>
#import <CNIOOpenSSL/dso.h>
#import <CNIOOpenSSL/ebcdic.h>
#import <CNIOOpenSSL/lhash.h>
#import <CNIOOpenSSL/obj_mac.h>
#import <CNIOOpenSSL/objects.h>
#import <CNIOOpenSSL/modes.h>
#import <CNIOOpenSSL/err.h>
#import <CNIOOpenSSL/evp.h>
#import <CNIOOpenSSL/hmac.h>
#import <CNIOOpenSSL/kssl.h>
#import <CNIOOpenSSL/e_os2.h>
#import <CNIOOpenSSL/ec.h>

/// Initialize OpenSSL.
///
/// This method is NOT THREAD SAFE. Please only call it from inside a lock or a pthread_once.
void CNIOOpenSSL_InitializeOpenSSL(void);

/// A no-op verify callback, for use from Swift.
int CNIOOpenSSL_noop_verify_callback(int preverify_ok, X509_STORE_CTX *context);

/// A small helper to allow querying whether we were build against LibreSSL or not.
///
/// Returns 1 if we built against LibreSSL, 0 if we did not.
int CNIOOpenSSL_is_libressl(void);

// This wrapper is used to erase the types required for this function. It's a bad
// thing to have to do, but until OpaquePointer gets better this is the only way to make
// this function work.
int CNIOOpenSSL_PKCS12_parse(void *p12, const char *pass, void **pkey, void **cert, void **ca);

// MARK: OpenSSL version shims
#if defined(SSL_OP_NO_TLSv1_3)
#define CNIOOpenSSL_SSL_OP_NO_TLSv1_3 SSL_OP_NO_TLSv1_3
#else
#define CNIOOpenSSL_SSL_OP_NO_TLSv1_3 0
#endif

// These are functions that shim over differences in different OpenSSL versions,
// which are best handled by using the C preprocessor.
void CNIOOpenSSL_SSL_CTX_setAutoECDH(SSL_CTX *ctx);
int CNIOOpenSSL_SSL_set_tlsext_host_name(SSL *ssl, const char *name);
const unsigned char *CNIOOpenSSL_ASN1_STRING_get0_data(ASN1_STRING *x);
const SSL_METHOD *CNIOOpenSSL_TLS_Method(void);
int CNIOOpenSSL_X509_up_ref(X509 *x);
int CNIOOpenSSL_SSL_get_ex_new_index(long argl, void *argp, CRYPTO_EX_new *new_func, CRYPTO_EX_dup *dup_func, CRYPTO_EX_free *free_func);

// MARK: Macro wrappers
// These are functions that rely on things declared in macros in OpenSSL, at least in
// some versions. The Swift compiler cannot expand C macros, so we need a file that
// can.
int CNIOOpenSSL_sk_GENERAL_NAME_num(STACK_OF(GENERAL_NAME) *x);
const GENERAL_NAME *CNIOOpenSSL_sk_GENERAL_NAME_value(STACK_OF(GENERAL_NAME) *x, int idx);
int CNIOOpenSSL_sk_X509_num(STACK_OF(X509) *x);
const X509 *CNIOOpenSSL_sk_X509_value(STACK_OF(X509) *x, int idx);
void CNIOOpenSSL_sk_X509_free(STACK_OF(X509) *x);
int CNIOOpenSSL_SSL_CTX_set_app_data(SSL_CTX *ctx, void *arg);
void *CNIOOpenSSL_SSL_CTX_get_app_data(SSL_CTX *ctx);
long CNIOOpenSSL_SSL_CTX_set_mode(SSL_CTX *ctx, long mode);
long CNIOOpenSSL_SSL_CTX_set_options(SSL_CTX *ctx, long options);
int CNIOOpenSSL_SSL_CTX_set_ciphersuites(SSL_CTX *ctx, const char *str);
void CNIOOpenSSL_OPENSSL_free(void *addr);
int CNIOOpenSSL_X509_set_notBefore(X509 *x, const ASN1_TIME *tm);
int CNIOOpenSSL_X509_set_notAfter(X509 *x, const ASN1_TIME *tm);
unsigned long CNIOOpenSSL_OpenSSL_version_num(void);

// We bring this typedef forward in case it's not present in the version of OpenSSL
// we have.
typedef int (*CNIOOpenSSL_SSL_CTX_alpn_select_cb_func)(SSL *ssl,
                                                          const unsigned char **out,
                                                          unsigned char *outlen,
                                                          const unsigned char *in,
                                                          unsigned int inlen,
                                                          void *arg);

int CNIOOpenSSL_SSL_CTX_set_alpn_protos(SSL_CTX *ctx,
                                        const unsigned char *protos,
                                        unsigned int protos_len);
void CNIOOpenSSL_SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx,
                                            CNIOOpenSSL_SSL_CTX_alpn_select_cb_func cb,
                                            void *arg);
void CNIOOpenSSL_SSL_get0_alpn_selected(const SSL *ssl,
                                        const unsigned char **data,
                                        unsigned int *len);
int CNIOOpenSSL_BIO_get_init(BIO *bio);
void CNIOOpenSSL_BIO_set_init(BIO *bio, int init);
void *CNIOOpenSSL_BIO_get_data(BIO *bio);
void CNIOOpenSSL_BIO_set_data(BIO *bio, void *ptr);
int CNIOOpenSSL_BIO_get_shutdown(BIO *bio);
void CNIOOpenSSL_BIO_set_shutdown(BIO *bio, int shut);
void CNIOOpenSSL_BIO_clear_retry_flags(BIO *bio);
void CNIOOpenSSL_BIO_set_retry_read(BIO *bio);
int CNIOOpenSSL_BIO_up_ref(BIO *bio);
int CNIOOpenSSL_BIO_should_retry(BIO *bio);
int CNIOOpenSSL_BIO_should_read(BIO *bio);
int CNIOOpenSSL_BIO_get_close(BIO *bio);
int CNIOOpenSSL_BIO_set_close(BIO *bio, long flag);
long CNIOOpenSSL_BIO_get_mem_data(BIO *bio, char **dataPtr);

// MARK: BIO helpers
/// This is a pointer to the BIO_METHOD structure for NIO's ByteBufferBIO.
///
/// This structure is always initialized at startup, and must be initialized in a
/// thread-safe manner. That means it should be guarded by some kind of pthread_once
/// setup behaviour, or a lock. For NIO, we use the initializeOpenSSL dance to do
/// this construction.
extern BIO_METHOD *CNIOOpenSSL_ByteBufferBIOMethod;

/// This is the type of the ByteBufferBIO created by Swift.
///
/// This type is used to create the BIO in Swift code. It can also be used to gate
/// initialization: if this is non-zero, we have already initialized ByteBufferBIOMethod
/// and can safely use it.
extern int CNIOOpenSSL_ByteBufferBIOType;

/// Initialize the `CNIOOpenSSL_ByteBufferBIOMethod` pointer with the values of
/// our specific ByteBuffer BIO type.
void CNIOOpenSSL_initByteBufferBIO(int (*bioWriteFunc)(void *, const char *, int),
                                   int (*bioReadFunc)(void *, char  *, int),
                                   int (*bioPutsFunc)(void *, const char *),
                                   int (*bioGetsFunc)(void *, char *, int),
                                   long (*bioCtrlFunc)(void *, int, long, void *),
                                   int (*bioCreateFunc)(void *),
                                   int (*bioDestroyFunc)(void *));


#endif /* openssl_h */
