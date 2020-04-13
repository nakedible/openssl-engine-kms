#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]
extern crate libc;
use bytes::Bytes;
use libc::{c_char, c_double, c_int, c_uchar, c_ulong, c_void};
use rusoto_core::Region;
use rusoto_kms::{Kms, KmsClient};
use std::collections::HashMap;
use std::ptr;
use std::sync::Mutex;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate log;
extern crate env_logger;

macro_rules! openssl_try {
    ($e:expr) => {{
        openssl_try!($e, 0, 0)
    }};
    ($e:expr, $exp:expr) => {{
        openssl_try!($e, $exp, 0)
    }};
    ($e:expr, $exp:expr, $ret:expr) => {{
        let ret = $e;
        if ret == $exp {
            error!("openssl call resulted in error: {}", ERR_peek_last_error());
            return $ret;
        }
        ret
    }};
}

unsafe fn from_buf_raw<T>(ptr: *const T, elts: usize) -> Vec<T> {
    let mut dst = Vec::with_capacity(elts);
    dst.set_len(elts);
    ptr::copy(ptr, dst.as_mut_ptr(), elts);
    dst
}

// OpenSSL header definitions
const OSSL_DYNAMIC_OLDEST: c_ulong = 0x00030000;

const NID_rsaEncryption: c_int = 6;
const NID_X9_62_id_ecPublicKey: c_int = 408;
const NID_sha1: c_int = 64;
const NID_sha256: c_int = 672;
const NID_sha384: c_int = 673;
const NID_sha512: c_int = 674;

const RSA_PKCS1_PADDING: c_int = 1;
const RSA_PKCS1_OAEP_PADDING: c_int = 4;
const RSA_PKCS1_PSS_PADDING: c_int = 6;

const EVP_PKEY_RSA: c_int = NID_rsaEncryption;
const EVP_PKEY_EC: c_int = NID_X9_62_id_ecPublicKey;
const EVP_PKEY_FLAG_AUTOARGLEN: c_int = 2;
const EVP_PKEY_ALG_CTRL: c_int = 0x1000;
const EVP_PKEY_CTRL_GET_MD: c_int = 13;
const EVP_PKEY_CTRL_GET_RSA_PADDING: c_int = EVP_PKEY_ALG_CTRL + 6;
const EVP_PKEY_CTRL_GET_RSA_OAEP_MD: c_int = EVP_PKEY_ALG_CTRL + 11;

type ENGINE = *mut c_void;
type EVP_PKEY = *mut c_void;
type EVP_PKEY_METHOD = *mut c_void;
type EVP_PKEY_CTX = *mut c_void;
type EVP_MD = *mut c_void;
type BIO = *mut c_void;

type pkey_init_fn = extern "C" fn(EVP_PKEY_CTX) -> c_int;
type pkey_sign_fn = extern "C" fn(EVP_PKEY_CTX, *mut c_uchar, *mut usize, *const c_uchar, usize) -> c_int;
type pkey_verify_fn = extern "C" fn(EVP_PKEY_CTX, *const c_uchar, usize, *const c_uchar, usize) -> c_int;
type pkey_encrypt_fn = extern "C" fn(EVP_PKEY_CTX, *mut c_uchar, *mut usize, *const c_uchar, c_int) -> c_int;
type pkey_decrypt_fn = extern "C" fn(EVP_PKEY_CTX, *mut c_uchar, *mut usize, *const c_uchar, c_int) -> c_int;

#[repr(C)]
pub struct dynamic_MEM_fns {
    dyn_MEM_malloc_fn: extern "C" fn(usize, *const c_char, c_int) -> *mut c_void,
    dyn_MEM_realloc_fn: extern "C" fn(*mut c_void, usize, *const c_char, c_int) -> *mut c_void,
    dyn_MEM_free_fn: extern "C" fn(*mut c_void, *const c_char, c_int),
}

#[repr(C)]
pub struct dynamic_fns {
    static_state: *mut c_void,
    mem_fns: dynamic_MEM_fns,
}

#[repr(C)]
pub struct rand_meth_st {
    seed: Option<extern "C" fn(*mut c_void, c_int) -> c_int>,
    bytes: Option<extern "C" fn(*mut c_uchar, c_int) -> c_int>,
    cleanup: Option<extern "C" fn()>,
    add: Option<extern "C" fn(*mut c_void, c_int, c_double) -> c_int>,
    pseudorand: Option<extern "C" fn(*mut c_uchar, c_int) -> c_int>,
    status: Option<extern "C" fn() -> c_int>,
}

extern "C" {
    fn ERR_peek_last_error() -> c_ulong;
    fn CRYPTO_set_mem_functions(
        m: extern "C" fn(usize, *const c_char, c_int) -> *mut c_void,
        r: extern "C" fn(*mut c_void, usize, *const c_char, c_int) -> *mut c_void,
        f: extern "C" fn(*mut c_void, *const c_char, c_int),
    ) -> c_int;
    fn ENGINE_get_static_state() -> *mut c_void;
    fn ENGINE_set_id(e: ENGINE, id: *const c_uchar) -> c_int;
    fn ENGINE_set_name(e: ENGINE, id: *const c_uchar) -> c_int;
    fn ENGINE_set_init_function(e: ENGINE, init_f: extern "C" fn(ENGINE) -> c_int) -> c_int;
    fn ENGINE_set_RAND(e: ENGINE, rand_meth: *const rand_meth_st) -> c_int;
    fn ENGINE_set_pkey_meths(e: ENGINE, f: extern "C" fn(ENGINE, *mut EVP_PKEY_METHOD, *mut *const c_int, c_int) -> c_int) -> c_int;
    fn ENGINE_set_load_privkey_function(
        e: ENGINE,
        loadpriv_f: extern "C" fn(ENGINE, *const c_char, *mut c_void, *mut c_void) -> EVP_PKEY,
    ) -> c_int;
    fn ENGINE_set_load_pubkey_function(
        e: ENGINE,
        loadpub_f: extern "C" fn(ENGINE, *const c_char, *mut c_void, *mut c_void) -> EVP_PKEY,
    ) -> c_int;
    fn EVP_PKEY_base_id(pkey: EVP_PKEY) -> c_int;
    fn EVP_PKEY_set1_engine(pkey: EVP_PKEY, e: ENGINE) -> c_int;
    fn EVP_PKEY_meth_new(id: c_int, flags: c_int) -> EVP_PKEY_METHOD;
    fn EVP_PKEY_meth_copy(dst: EVP_PKEY_METHOD, src: EVP_PKEY_METHOD);
    fn EVP_PKEY_meth_find(typ: c_int) -> EVP_PKEY_METHOD;
    fn EVP_PKEY_meth_set_encrypt(pmeth: EVP_PKEY_METHOD, encrypt_init: pkey_init_fn, encrypt: pkey_encrypt_fn);
    fn EVP_PKEY_meth_set_decrypt(pmeth: EVP_PKEY_METHOD, decrypt_init: pkey_init_fn, decrypt: pkey_decrypt_fn);
    fn EVP_PKEY_meth_set_sign(pmeth: EVP_PKEY_METHOD, sign_init: pkey_init_fn, sign: pkey_sign_fn);
    fn EVP_PKEY_meth_set_verify(pmeth: EVP_PKEY_METHOD, verify_init: pkey_init_fn, verify: pkey_verify_fn);
    fn EVP_PKEY_CTX_get0_pkey(ctx: EVP_PKEY_CTX) -> EVP_PKEY;
    fn EVP_PKEY_CTX_ctrl(ctx: EVP_PKEY_CTX, keytype: c_int, optype: c_int, cmd: c_int, p1: c_int, p2: *mut c_void) -> c_int;
    fn EVP_MD_type(md: EVP_MD) -> c_int;
    fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> BIO;
    fn BIO_free(a: BIO) -> c_int;
    fn d2i_PUBKEY_bio(bp: BIO, a: *mut EVP_PKEY) -> EVP_PKEY;
}

// Static globals
const ENGINE_ID: &str = "kms\0";
const ENGINE_NAME: &str = "AWS KMS based engine\0";

static RAND_METH: rand_meth_st = rand_meth_st {
    seed: None,
    bytes: Some(rand_bytes),
    cleanup: None,
    add: None,
    pseudorand: Some(rand_bytes),
    status: Some(rand_status),
};

lazy_static! {
    static ref KMS_CLIENT: KmsClient = KmsClient::new(Region::default());
    static ref KEYS: Mutex<HashMap<usize, String>> = Mutex::new(HashMap::new());
}

// implementation functions
unsafe fn get_alg(ctx: EVP_PKEY_CTX) -> Result<&'static str, String> {
    let mut padding: c_int = 0;
    let mut md: EVP_MD = ptr::null_mut();
    let key_type = EVP_PKEY_base_id(EVP_PKEY_CTX_get0_pkey(ctx));
    if key_type == EVP_PKEY_RSA {
        EVP_PKEY_CTX_ctrl(ctx, -1, -1, EVP_PKEY_CTRL_GET_RSA_PADDING, 0, &mut padding as *mut _ as *mut c_void);
    }
    let md_cmd = if padding == RSA_PKCS1_OAEP_PADDING {
        EVP_PKEY_CTRL_GET_RSA_OAEP_MD
    } else {
        EVP_PKEY_CTRL_GET_MD
    };
    EVP_PKEY_CTX_ctrl(ctx, -1, -1, md_cmd, 0, &mut md as *mut _ as *mut c_void);
    if md.is_null() {
        return Err("could not get md from pkey".to_string());
    }
    let md_type = EVP_MD_type(md);
    match (key_type, padding, md_type) {
        (EVP_PKEY_RSA, RSA_PKCS1_PADDING, NID_sha256) => Ok("RSASSA_PKCS1_V1_5_SHA_256"),
        (EVP_PKEY_RSA, RSA_PKCS1_PADDING, NID_sha384) => Ok("RSASSA_PKCS1_V1_5_SHA_384"),
        (EVP_PKEY_RSA, RSA_PKCS1_PADDING, NID_sha512) => Ok("RSASSA_PKCS1_V1_5_SHA_512"),
        (EVP_PKEY_RSA, RSA_PKCS1_PSS_PADDING, NID_sha256) => Ok("RSASSA_PSS_SHA_256"),
        (EVP_PKEY_RSA, RSA_PKCS1_PSS_PADDING, NID_sha384) => Ok("RSASSA_PSS_SHA_384"),
        (EVP_PKEY_RSA, RSA_PKCS1_PSS_PADDING, NID_sha512) => Ok("RSASSA_PSS_SHA_512"),
        (EVP_PKEY_RSA, RSA_PKCS1_OAEP_PADDING, NID_sha1) => Ok("RSAES_OAEP_SHA_1"),
        (EVP_PKEY_RSA, RSA_PKCS1_OAEP_PADDING, NID_sha256) => Ok("RSAES_OAEP_SHA_256"),
        (EVP_PKEY_EC, _, NID_sha256) => Ok("ECDSA_SHA_256"),
        (EVP_PKEY_EC, _, NID_sha384) => Ok("ECDSA_SHA_384"),
        (EVP_PKEY_EC, _, NID_sha512) => Ok("ECDSA_SHA_512"),
        _ => Err(format!("unsupported key type {}, padding {} or md {}", key_type, padding, md_type)),
    }
}

unsafe fn get_key_id(ctx: EVP_PKEY_CTX) -> String {
    let pkey = EVP_PKEY_CTX_get0_pkey(ctx);
    KEYS.lock()
        .unwrap()
        .get(&(pkey as usize))
        .expect("could not find key id for pkey")
        .to_string()
}

extern "C" fn kms_init(_e: ENGINE) -> c_int {
    env_logger::init_from_env("OPENSSL_ENGINE_KMS_LOG");
    debug!("kms_init");
    return 1;
}

extern "C" fn rand_bytes(buf: *mut c_uchar, num: c_int) -> c_int {
    trace!("rand_bytes num {}", num);
    let req = rusoto_kms::GenerateRandomRequest {
        custom_key_store_id: None,
        number_of_bytes: Some(num.into()),
    };
    let output = KMS_CLIENT.generate_random(req).sync();
    if let Err(e) = output {
        error!("generate {} random bytes failed: {}", num, e);
        return 0;
    }
    let bytes = output.unwrap().plaintext.expect("plaintext was not returned");
    unsafe {
        buf.copy_from(bytes.as_ptr(), num as usize);
    }
    return 1;
}

extern "C" fn rand_status() -> c_int {
    return 1;
}

extern "C" fn kms_common_init(_ctx: EVP_PKEY_CTX) -> c_int {
    return 1;
}

extern "C" fn kms_sign(ctx: EVP_PKEY_CTX, sig: *mut c_uchar, siglen: *mut usize, tbs: *const c_uchar, tbslen: usize) -> c_int {
    trace!("kms_sign");
    let message = unsafe { from_buf_raw(tbs, tbslen) };
    let key_id = unsafe { get_key_id(ctx) };
    let alg = unsafe { get_alg(ctx) };
    if let Err(e) = alg {
        error!("could not determine algorithm: {}", e);
        return 0;
    }
    let req = rusoto_kms::SignRequest {
        key_id: key_id.to_string(),
        message: Bytes::from(message),
        message_type: Some("DIGEST".to_string()),
        signing_algorithm: alg.unwrap().to_string(),
        grant_tokens: None,
    };
    let output = KMS_CLIENT.sign(req).sync();
    if let Err(e) = output {
        error!("sign err for key id {}: {}", key_id, e);
        return 0;
    }
    let bytes = output.unwrap().signature.expect("signature was not returned");
    unsafe {
        sig.copy_from(bytes.as_ptr(), bytes.len());
        *siglen = bytes.len();
    }
    return 1;
}

extern "C" fn kms_verify(ctx: EVP_PKEY_CTX, sig: *const c_uchar, siglen: usize, tbs: *const c_uchar, tbslen: usize) -> c_int {
    trace!("kms_verify");
    let message = unsafe { from_buf_raw(tbs, tbslen) };
    let signature = unsafe { from_buf_raw(sig, siglen) };
    let key_id = unsafe { get_key_id(ctx) };
    let alg = unsafe { get_alg(ctx) };
    if let Err(e) = alg {
        error!("could not determine algorithm: {}", e);
        return 0;
    }
    let req = rusoto_kms::VerifyRequest {
        key_id: key_id.to_string(),
        signature: Bytes::from(signature),
        message: Bytes::from(message),
        message_type: Some("DIGEST".to_string()),
        signing_algorithm: alg.unwrap().to_string(),
        grant_tokens: None,
    };
    let output = KMS_CLIENT.verify(req).sync();
    if let Err(e) = output {
        match e {
            rusoto_core::RusotoError::Unknown(x) if x.body_as_str().contains("KMSInvalidSignatureException") => {
                trace!("invalid signature for key id {}", key_id)
            }
            x => error!("verify err for key id {}: {:?}", key_id, x),
        }
        return 0;
    }
    assert_eq!(output.unwrap().signature_valid.unwrap(), true);
    return 1;
}

extern "C" fn kms_encrypt(ctx: EVP_PKEY_CTX, out: *mut c_uchar, outlen: *mut usize, in_: *const c_uchar, inlen: c_int) -> c_int {
    trace!("kms_encrypt");
    let plaintext = unsafe { from_buf_raw(in_, inlen as usize) };
    let key_id = unsafe { get_key_id(ctx) };
    let alg = unsafe { get_alg(ctx) };
    if let Err(e) = alg {
        error!("could not determine algorithm: {}", e);
        return 0;
    }
    let req = rusoto_kms::EncryptRequest {
        key_id: key_id.to_string(),
        plaintext: Bytes::from(plaintext),
        encryption_algorithm: Some(alg.unwrap().to_string()),
        encryption_context: None,
        grant_tokens: None,
    };
    let output = KMS_CLIENT.encrypt(req).sync();
    if let Err(e) = output {
        error!("encrypt err for key id {}: {}", key_id, e);
        return 0;
    }
    let bytes = output.unwrap().ciphertext_blob.expect("ciphertext was not returned");
    unsafe {
        out.copy_from(bytes.as_ptr(), bytes.len());
        *outlen = bytes.len();
    }
    return 1;
}

extern "C" fn kms_decrypt(ctx: EVP_PKEY_CTX, out: *mut c_uchar, outlen: *mut usize, in_: *const c_uchar, inlen: c_int) -> c_int {
    trace!("kms_decrypt");
    let ciphertext = unsafe { from_buf_raw(in_, inlen as usize) };
    let key_id = unsafe { get_key_id(ctx) };
    let alg = unsafe { get_alg(ctx) };
    if let Err(e) = alg {
        error!("could not determine algorithm: {}", e);
        return 0;
    }
    let req = rusoto_kms::DecryptRequest {
        key_id: Some(key_id.to_string()),
        ciphertext_blob: Bytes::from(ciphertext),
        encryption_algorithm: Some(alg.unwrap().to_string()),
        encryption_context: None,
        grant_tokens: None,
    };
    let output = KMS_CLIENT.decrypt(req).sync();
    if let Err(e) = output {
        error!("decrypt err for key id {}: {}", key_id, e);
        return 0;
    }
    let bytes = output.unwrap().plaintext.expect("plaintext was not returned");
    unsafe {
        out.copy_from(bytes.as_ptr(), bytes.len());
        *outlen = bytes.len();
    }
    return 1;
}

extern "C" fn pkey_meths(_e: ENGINE, pmeth: *mut EVP_PKEY_METHOD, _nids: *mut *const c_int, nid: c_int) -> c_int {
    if pmeth.is_null() {
        return 0;
    } else {
        unsafe {
            let pkey_meth = openssl_try!(EVP_PKEY_meth_new(nid, EVP_PKEY_FLAG_AUTOARGLEN), ptr::null_mut());
            let orig_meth = openssl_try!(EVP_PKEY_meth_find(nid), ptr::null_mut());
            EVP_PKEY_meth_copy(pkey_meth, orig_meth);
            EVP_PKEY_meth_set_sign(pkey_meth, kms_common_init, kms_sign);
            EVP_PKEY_meth_set_decrypt(pkey_meth, kms_common_init, kms_decrypt);
            if !std::env::var("OPENSSL_ENGINE_KMS_USE_PUBKEY").unwrap_or("".to_string()).is_empty() {
                EVP_PKEY_meth_set_verify(pkey_meth, kms_common_init, kms_verify);
                EVP_PKEY_meth_set_encrypt(pkey_meth, kms_common_init, kms_encrypt);
            }
            *pmeth = pkey_meth;
        }
        return 1;
    }
}

extern "C" fn load_key(e: ENGINE, key_id: *const c_char, _ui_method: *mut c_void, _callback_data: *mut c_void) -> EVP_PKEY {
    let key_id = unsafe { std::ffi::CStr::from_ptr(key_id).to_str().unwrap() };
    trace!("load_key for key id {}", key_id);
    let req = rusoto_kms::GetPublicKeyRequest {
        key_id: key_id.to_string(),
        grant_tokens: None,
    };
    let output = KMS_CLIENT.get_public_key(req).sync();
    if let Err(e) = output {
        error!("load key err for key id {}: {}", key_id, e);
        return ptr::null_mut();
    }
    let bytes = output.unwrap().public_key.expect("public key not returned");
    unsafe {
        let key_bio = openssl_try!(
            BIO_new_mem_buf(bytes.as_ptr() as *const c_void, bytes.len() as c_int),
            ptr::null_mut(),
            ptr::null_mut()
        );
        let pubkey = d2i_PUBKEY_bio(key_bio, std::ptr::null_mut());
        openssl_try!(BIO_free(key_bio), 0, ptr::null_mut());
        if pubkey.is_null() {
            return ptr::null_mut();
        }
        KEYS.lock().unwrap().insert(pubkey as usize, key_id.to_string());
        openssl_try!(EVP_PKEY_set1_engine(pubkey, e), 0, ptr::null_mut());
        return pubkey;
    }
}

// openssl engine entry points
#[no_mangle]
pub extern "C" fn v_check(v: c_ulong) -> c_ulong {
    if v >= OSSL_DYNAMIC_OLDEST {
        OSSL_DYNAMIC_OLDEST
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn bind_engine(e: ENGINE, _id: *const c_char, fns: *const dynamic_fns) -> c_int {
    unsafe {
        if ENGINE_get_static_state() != (*fns).static_state {
            openssl_try!(CRYPTO_set_mem_functions(
                (*fns).mem_fns.dyn_MEM_malloc_fn,
                (*fns).mem_fns.dyn_MEM_realloc_fn,
                (*fns).mem_fns.dyn_MEM_free_fn
            ));
        }
        openssl_try!(ENGINE_set_id(e, ENGINE_ID.as_ptr()));
        openssl_try!(ENGINE_set_name(e, ENGINE_NAME.as_ptr()));
        openssl_try!(ENGINE_set_init_function(e, kms_init));
        openssl_try!(ENGINE_set_pkey_meths(e, pkey_meths));
        openssl_try!(ENGINE_set_load_privkey_function(e, load_key));
        openssl_try!(ENGINE_set_load_pubkey_function(e, load_key));
        if !std::env::var("OPENSSL_ENGINE_KMS_USE_RAND").unwrap_or("".to_string()).is_empty() {
            openssl_try!(ENGINE_set_RAND(e, &RAND_METH));
        }
    }
    return 1;
}
