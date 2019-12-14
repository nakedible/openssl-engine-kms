#![allow(non_snake_case, non_upper_case_globals, non_camel_case_types)]
extern crate libc;
use std::ptr;
use std::collections::HashMap;
use std::sync::Mutex;
use libc::{c_void, c_char, c_uchar, c_int, c_uint, c_long, c_ulong, c_double};
use rusoto_core::Region;
use rusoto_kms::{Kms, KmsClient};
use bytes::Bytes;

#[macro_use]
extern crate lazy_static;

macro_rules! openssl_try {
  ($e:expr) => ({
    openssl_try!($e, 0);
  });
  ($e:expr, $exp:expr) => ({
    let ret = $e;
    if ret == $exp {
      println!("failed!"); // FIXME: get ssl error and print it
      return 0;
    }
    ret
  });
}

unsafe fn from_buf_raw<T>(ptr: *const T, elts: usize) -> Vec<T> {
  let mut dst = Vec::with_capacity(elts);
  dst.set_len(elts);
  ptr::copy(ptr, dst.as_mut_ptr(), elts);
  dst
}

// OpenSSL header definitions
const OSSL_DYNAMIC_OLDEST : c_ulong = 0x00030000;

const RSA_PKCS1_OAEP_PADDING : c_int = 4;

const EVP_PKEY_RSA : c_int = 6;
const EVP_PKEY_EC : c_int = 408;
const EVP_PKEY_FLAG_AUTOARGLEN : c_int = 2;
const EVP_PKEY_ALG_CTRL : c_int = 0x1000;
const EVP_PKEY_CTRL_GET_RSA_PADDING : c_int = EVP_PKEY_ALG_CTRL + 6;
const EVP_PKEY_CTRL_GET_RSA_OAEP_MD : c_int = EVP_PKEY_ALG_CTRL + 11;
const EVP_PKEY_OP_ENCRYPT : c_int = 1<<8;
const EVP_PKEY_OP_DECRYPT : c_int = 1<<9;
const EVP_PKEY_OP_TYPE_CRYPT : c_int = EVP_PKEY_OP_ENCRYPT | EVP_PKEY_OP_DECRYPT;
const NID_sha1 : c_int = 64;
const NID_sha256 : c_int = 672;

static EVP_NIDS : [c_int; 2] = [EVP_PKEY_RSA, EVP_PKEY_EC];

type ENGINE = *mut c_void;
type EVP_PKEY = *mut c_void;
type EVP_PKEY_METHOD = *mut c_void;
type EVP_PKEY_CTX = *mut c_void;
type EVP_MD = *mut c_void;
type RSA = *mut c_void;
type BIO = *mut c_void;

#[allow(non_snake_case)]
#[repr(C)]
pub struct dynamic_fns {
  static_state: *mut c_void,
  dyn_MEM_malloc_fn: *mut c_void,
  dyn_MEM_realloc_fn: *mut c_void,
  dyn_MEM_free_fn: *mut c_void,
}

#[repr(C)]
pub struct rand_meth_st {
  seed: Option<extern fn(*mut c_void, c_int) -> c_int>,
  bytes: Option<extern fn(*mut c_uchar, c_int) -> c_int>, 
  cleanup: Option<extern fn()>,
  add: Option<extern fn(*mut c_void, c_int, c_double) -> c_int>,
  pseudorand: Option<extern fn(*mut c_uchar, c_int) -> c_int>, 
  status: Option<extern fn() -> c_int>
}

extern {
  fn ENGINE_get_static_state() -> *mut c_void;
  fn CRYPTO_set_mem_functions(m: *mut c_void, r: *mut c_void, f: *mut c_void) -> c_int;
  fn ENGINE_set_id(e: ENGINE, id: *const c_uchar) -> c_int;
  fn ENGINE_set_name(e: ENGINE, id: *const c_uchar) -> c_int;
  fn ENGINE_set_init_function(e: ENGINE, init_f: extern fn(ENGINE) -> c_int) -> c_int;
  fn ENGINE_set_RAND(e: ENGINE, rand_meth: *const rand_meth_st) -> c_int;
  fn ENGINE_set_pkey_meths(e: ENGINE, f: extern fn(e: ENGINE, pmeth: *mut EVP_PKEY_METHOD, nids: *mut *const c_int, nid: c_int) -> c_int) -> c_int;
  fn ENGINE_set_load_privkey_function(e: ENGINE, loadpriv_f: extern fn(ENGINE, *const c_char, *mut c_void, *mut c_void) -> EVP_PKEY) -> c_int;
  fn ENGINE_set_load_pubkey_function(e: ENGINE, loadpub_f: extern fn(ENGINE, *const c_char, *mut c_void, *mut c_void) -> EVP_PKEY) -> c_int;
  fn EVP_PKEY_get1_RSA(pkey: EVP_PKEY) -> RSA;
  fn EVP_PKEY_bits(pkey: EVP_PKEY) -> c_int;
  fn EVP_PKEY_meth_new(id: c_int, flags: c_int) -> EVP_PKEY_METHOD;
  fn EVP_PKEY_meth_copy(dst: EVP_PKEY_METHOD, src: EVP_PKEY_METHOD);
  fn EVP_PKEY_meth_find(typ: c_int) -> EVP_PKEY_METHOD;
  fn EVP_PKEY_meth_set_decrypt(pmeth: EVP_PKEY_METHOD, decrypt_init: extern fn(ctx: EVP_PKEY_CTX) -> c_int, decrypt: extern fn(ctx: EVP_PKEY_CTX, out: *mut c_uchar, outlen: *mut usize, in_: *const c_uchar, inlen: c_int) -> c_int);
  fn EVP_PKEY_CTX_get0_pkey(ctx: EVP_PKEY_CTX) -> EVP_PKEY;
  fn EVP_PKEY_CTX_ctrl(ctx: EVP_PKEY_CTX, keytype: c_int, optype: c_int, cmd: c_int, p1: c_int, p2: *mut c_void) -> c_int;
  fn EVP_MD_type(md: EVP_MD) -> c_int;
  fn BIO_new_mem_buf(buf: *const c_void, len: c_int) -> BIO;
  fn d2i_PUBKEY_bio(bp: BIO, a: *mut EVP_PKEY) -> EVP_PKEY;
}

// Static globals
const ENGINE_ID : &str = "kms\0";
const ENGINE_NAME : &str = "AWS KMS based engine\0";

static RAND_METH : rand_meth_st = rand_meth_st {
  seed: None,
  bytes: Some(rand_bytes),
  cleanup: None,
  add: None,
  pseudorand: Some(rand_bytes),
  status: Some(rand_status)
};

#[derive(Debug)]
enum KeyUsage {
  None,
  SignVerify,
  EncryptDecrypt
}

#[derive(Debug)]
struct KeyInfo {
  usage: KeyUsage,
  key_id: String
}

lazy_static! {
  static ref KMS_CLIENT : KmsClient = KmsClient::new(Region::EuWest1);
  static ref KEYS : Mutex<HashMap<usize, KeyInfo>> = Mutex::new(HashMap::new());
}

// implementation functions
extern fn kms_init(_e: ENGINE) -> c_int {
  println!("kms_init");
  return 1;
}

extern fn rand_bytes(buf: *mut c_uchar, num: c_int) -> c_int {
  let req = rusoto_kms::GenerateRandomRequest {
    custom_key_store_id: None,
    number_of_bytes: Some(num.into())
  };
  let output = KMS_CLIENT.generate_random(req).sync().expect("kms generate_random failed");
  let bytes = output.plaintext.expect("plaintext was not returned");
  println!("FIXME DEBUG bytes: {:?}", bytes);
  unsafe {
    buf.copy_from(bytes.as_ptr(), num as usize);
  }
  return 1;
}

extern fn rand_status() -> c_int {
  return 1;
}

extern fn rsa_decrypt_init(_ctx: EVP_PKEY_CTX) -> c_int {
  println!("decrypt init!");
  return 1;
}

extern fn rsa_decrypt(ctx: EVP_PKEY_CTX, out: *mut c_uchar, outlen: *mut usize, in_: *const c_uchar, inlen: c_int) -> c_int {
  println!("decrypt!");
  let ciphertext = unsafe { from_buf_raw(in_, inlen as usize) };
  let rsa = unsafe { EVP_PKEY_get1_RSA(EVP_PKEY_CTX_get0_pkey(ctx)) };
  let keys = KEYS.lock().unwrap();
  let key_info = keys.get(&(rsa as usize)).expect("could not find key info");
  let key_id = &key_info.key_id;
  let alg;
  unsafe {
    let mut padding : c_int = 0;
    let mut md : EVP_MD = ptr::null_mut();
    openssl_try!(EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_DECRYPT, EVP_PKEY_CTRL_GET_RSA_PADDING, 0, &mut padding as *mut _ as *mut c_void));
    if padding != RSA_PKCS1_OAEP_PADDING { panic!("not oaep"); }
    openssl_try!(EVP_PKEY_CTX_ctrl(ctx, EVP_PKEY_RSA, EVP_PKEY_OP_DECRYPT, EVP_PKEY_CTRL_GET_RSA_OAEP_MD, 0, &mut md as *mut _ as *mut c_void));
    let md_type = EVP_MD_type(md);
    if md_type == NID_sha1 {
      alg = Some("RSAES_OAEP_SHA_1".to_string());
    } else if md_type == NID_sha256 {
      alg = Some("RSAES_OAEP_SHA_256".to_string());
    } else {
      panic!("unsupported md");
    }
  }
  let req = rusoto_kms::DecryptRequest {
    ciphertext_blob: Bytes::from(ciphertext),
    encryption_algorithm: alg,
    encryption_context: None,
    grant_tokens: None,
    key_id: Some(key_id.to_string())
  };
  let output = KMS_CLIENT.decrypt(req).sync().expect("kms decrypt failed");
  let bytes = output.plaintext.expect("plaintext was not returned");
  println!("decrypt bytes {:?}", bytes);
  unsafe {
    out.copy_from(bytes.as_ptr(), bytes.len());
    *outlen = bytes.len();
  }
  return 1;
}

extern fn pkey_meths(_e: ENGINE, pmeth: *mut EVP_PKEY_METHOD, nids: *mut *const c_int, nid: c_int) -> c_int {
  if pmeth == ptr::null_mut() {
    unsafe { *nids = EVP_NIDS.as_ptr(); }
    return EVP_NIDS.len() as c_int;
  } else if nid == EVP_PKEY_RSA {
    println!("want rsa");
    unsafe {
      let pkey_meth = EVP_PKEY_meth_new(EVP_PKEY_RSA, EVP_PKEY_FLAG_AUTOARGLEN);
      let orig_meth = EVP_PKEY_meth_find(EVP_PKEY_RSA);
      EVP_PKEY_meth_copy(pkey_meth, orig_meth);
      EVP_PKEY_meth_set_decrypt(pkey_meth, rsa_decrypt_init, rsa_decrypt);
      *pmeth = pkey_meth;
    }
    return 1;
  } else if nid == EVP_PKEY_EC {
    println!("want ec");
  } else {
    panic!("aiee");
  }
  return 0;
}

extern fn load_privkey(_e: ENGINE, key_id: *const c_char, _ui_method: *mut c_void, _callback_data: *mut c_void) -> EVP_PKEY {
  println!("load_privkey");
  let key_id = unsafe { std::ffi::CStr::from_ptr(key_id).to_str().unwrap() };
  let req = rusoto_kms::GetPublicKeyRequest {
    grant_tokens: None,
    key_id: key_id.to_string()
  };
  let output = KMS_CLIENT.get_public_key(req).sync().expect("kms get public key failed");
  let bytes = output.public_key.expect("public key not returned");
  let key_info = KeyInfo {
    usage: match output.key_usage.unwrap_or("NONE".to_string()).as_str() {
      "NONE" => KeyUsage::None,
      "SIGN_VERIFY" => KeyUsage::SignVerify,
      "ENCRYPT_DECRYPT" => KeyUsage::EncryptDecrypt,
      _ => panic!("aiee")
    },
    key_id: key_id.to_string()
  };
  println!("key_info: {:?}", &key_info);
  unsafe {
    let key_bio = BIO_new_mem_buf(bytes.as_ptr() as *const c_void, bytes.len() as c_int);
    let pubkey = d2i_PUBKEY_bio(key_bio, std::ptr::null_mut());
    println!("bits: {}", EVP_PKEY_bits(pubkey));
    let rsa = EVP_PKEY_get1_RSA(pubkey);
    KEYS.lock().unwrap().insert(rsa as usize, key_info);
    //let rsa = RSA_new();
    // RSA_set_method
    //openssl_try!(EVP_PKEY_assign(key, EVP_PKEY_RSA, rsa));
    // RSA_set_app_data
    // RSA_set0_key
    // RSA_set0_factors
    // RSA_set0_crt_params
    return pubkey;
  }
}

// openssl engine entry points
#[no_mangle]
pub extern fn v_check(v: c_ulong) -> c_ulong {
  //println!("v_check {}", v);
  if v >= OSSL_DYNAMIC_OLDEST { OSSL_DYNAMIC_OLDEST } else { 0 }
}

#[no_mangle]
pub extern fn bind_engine(e: ENGINE, _id: *const c_char, fns: *const dynamic_fns) -> c_int {
  //println!("bind_engine");
  unsafe {
    if ENGINE_get_static_state() != (*fns).static_state {
      openssl_try!(CRYPTO_set_mem_functions((*fns).dyn_MEM_malloc_fn, (*fns).dyn_MEM_realloc_fn, (*fns).dyn_MEM_free_fn));
    }
    openssl_try!(ENGINE_set_id(e, ENGINE_ID.as_ptr()));
    openssl_try!(ENGINE_set_name(e, ENGINE_NAME.as_ptr()));
    openssl_try!(ENGINE_set_init_function(e, kms_init));
    openssl_try!(ENGINE_set_RAND(e, &RAND_METH));
    openssl_try!(ENGINE_set_pkey_meths(e, pkey_meths));
    openssl_try!(ENGINE_set_load_privkey_function(e, load_privkey));
    openssl_try!(ENGINE_set_load_pubkey_function(e, load_privkey));
  }
  return 1;
}
