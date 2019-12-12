extern crate libc;
use libc::{c_void, c_char, c_uchar, c_int, c_uint, c_long, c_ulong, c_double};
use rusoto_core::Region;
use rusoto_kms::{Kms, KmsClient};

#[macro_use]
extern crate lazy_static;

macro_rules! openssl_try {
    ($e:expr) => ({
        let ret = $e;
        if ret != 1 {
          println!("failed!");
          return ret;
        }
    })
}

// OpenSSL header definitions
const OSSL_DYNAMIC_OLDEST : c_ulong = 0x00030000;

const RSA_FLAG_EXT_PKEY : c_int = 0x0020;

const EVP_PKEY_RSA : c_int = 6;

type ENGINE = *mut c_void;
type RSA_METHOD = *mut c_void;
type EVP_PKEY = *mut c_void;
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
  fn ENGINE_set_RSA(e: ENGINE, rsa: RSA_METHOD) -> c_int;
  fn ENGINE_set_RAND(e: ENGINE, rand_meth: *const rand_meth_st) -> c_int;
  fn ENGINE_set_load_privkey_function(e: ENGINE, loadpriv_f: extern fn(ENGINE, *const c_char, *mut c_void, *mut c_void) -> EVP_PKEY) -> c_int;
  fn ENGINE_set_load_pubkey_function(e: ENGINE, loadpub_f: extern fn(ENGINE, *const c_char, *mut c_void, *mut c_void) -> EVP_PKEY) -> c_int;
  fn RSA_get_default_method() -> RSA_METHOD;
  fn RSA_meth_dup(meth: RSA_METHOD) -> RSA_METHOD;
  fn RSA_meth_set1_name(meth: RSA_METHOD, name: *const c_uchar) -> c_int;
  fn RSA_meth_set_flags(meth: RSA_METHOD, flags: c_int) -> c_int;
  fn RSA_meth_set_priv_enc(meth: RSA_METHOD, priv_enc: extern fn(flen: c_int, from: *const c_uchar, to: *mut c_uchar, rsa: RSA, padding: c_int) -> c_int) -> c_int;
  fn RSA_meth_set_priv_dec(meth: RSA_METHOD, priv_dec: extern fn(flen: c_int, from: *const c_uchar, to: *mut c_uchar, rsa: RSA, padding: c_int) -> c_int) -> c_int;
  fn RSA_meth_set_finish(meth: RSA_METHOD) -> c_int;
  fn RSA_meth_set0_app_data(meth: RSA_METHOD, app_data: *const c_void) -> c_int;
  fn RSA_meth_get0_app_data(meth: RSA_METHOD) -> *mut c_void;
  fn RSA_new() -> RSA;
  fn EVP_PKEY_new() -> EVP_PKEY;
  fn EVP_PKEY_assign(pkey: EVP_PKEY, pkey_type: c_int, rsa: RSA) -> c_int;
  fn EVP_PKEY_get1_RSA(pkey: EVP_PKEY) -> RSA;
  fn EVP_PKEY_set1_engine(pkey: EVP_PKEY, e: ENGINE) -> c_int;
  fn EVP_PKEY_bits(pkey: EVP_PKEY) -> c_int;
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

lazy_static! {
  static ref KMS_CLIENT : KmsClient = KmsClient::new(Region::EuWest1);
}

// implementation functions
extern fn kms_init(e: ENGINE) -> c_int {
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

extern fn rsa_priv_enc(flen: c_int, from: *const c_uchar, to: *mut c_uchar, rsa: RSA, padding: c_int) -> c_int {
  println!("priv enc");
  return 0;
}

extern fn rsa_priv_dec(flen: c_int, from: *const c_uchar, to: *mut c_uchar, rsa: RSA, padding: c_int) -> c_int {
  println!("priv dec");
  unsafe {
    let ptr = RSA_meth_get0_app_data(rsa);
    println!("ptr {:?}", ptr);
  }
  return 0;
}

extern fn load_privkey(e: ENGINE, key_id: *const c_char, ui_method: *mut c_void, callback_data: *mut c_void) -> EVP_PKEY {
  println!("load_privkey");
  let key_id = unsafe { std::ffi::CStr::from_ptr(key_id).to_str().unwrap().to_string() };
  let req = rusoto_kms::GetPublicKeyRequest {
    grant_tokens: None,
    key_id: key_id
  };
  let output = KMS_CLIENT.get_public_key(req).sync().expect("kms get public key failed");
  let bytes = output.public_key.expect("public key not returned");
  unsafe {
    let key_bio = BIO_new_mem_buf(bytes.as_ptr() as *const c_void, bytes.len() as c_int);
    let pubkey = d2i_PUBKEY_bio(key_bio, std::ptr::null_mut());
    println!("bits: {}", EVP_PKEY_bits(pubkey));
    let rsa = EVP_PKEY_get1_RSA(pubkey);
    let ptr = "foo".as_ptr() as *const c_void;
    println!("ptr {:?}", ptr);
    assert_eq!(RSA_meth_set0_app_data(rsa, ptr), 1);
    //println!("keyval {:?} {:?}", key, newkey);
    //let rsa = RSA_new();
    // RSA_set_method
    //assert_eq!(EVP_PKEY_assign(key, EVP_PKEY_RSA, rsa), 1);
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
    assert_eq!(ENGINE_set_name(e, ENGINE_NAME.as_ptr()), 1);
    assert_eq!(ENGINE_set_init_function(e, kms_init), 1);
    let ops = RSA_meth_dup(RSA_get_default_method()); // check for null return
    assert_eq!(RSA_meth_set1_name(ops, "KMS RSA method\0".as_ptr()), 1);
    assert_eq!(RSA_meth_set_flags(ops, RSA_FLAG_EXT_PKEY), 1);
    assert_eq!(RSA_meth_set_priv_enc(ops, rsa_priv_enc), 1);
    assert_eq!(RSA_meth_set_priv_dec(ops, rsa_priv_dec), 1);
    assert_eq!(ENGINE_set_RSA(e, ops), 1);
    assert_eq!(ENGINE_set_RAND(e, &RAND_METH), 1);
    assert_eq!(ENGINE_set_load_privkey_function(e, load_privkey), 1);
    assert_eq!(ENGINE_set_load_pubkey_function(e, load_privkey), 1);
  }
  return 1;
}

/*
	ops = RSA_meth_dup(RSA_get_default_method());
		if (ops == NULL)
			return NULL;
		RSA_meth_set1_name(ops, "libp11 RSA method");
		RSA_meth_set_flags(ops, 0);
		RSA_meth_set_priv_enc(ops, pkcs11_rsa_priv_enc_method);
		RSA_meth_set_priv_dec(ops, pkcs11_rsa_priv_dec_method);
		RSA_meth_set_finish(ops, pkcs11_rsa_free_method);
*/
