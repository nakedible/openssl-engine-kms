extern crate libc;
use rusoto_core::Region;
use rusoto_kms::{Kms, KmsClient};

#[macro_use]
extern crate lazy_static;

// OpenSSL header definitions
const OSSL_DYNAMIC_OLDEST : libc::c_ulong = 0x00030000;

type ENGINE = *mut libc::c_void;
type RSA_METHOD = *mut libc::c_void;

#[allow(non_snake_case)]
#[repr(C)]
pub struct dynamic_fns {
  static_state: *mut libc::c_void,
  dyn_MEM_malloc_fn: *mut libc::c_void,
  dyn_MEM_realloc_fn: *mut libc::c_void,
  dyn_MEM_free_fn: *mut libc::c_void,
}

#[repr(C)]
pub struct rand_meth_st {
  seed: Option<extern fn(*mut libc::c_void, libc::c_int) -> libc::c_int>,
  bytes: Option<extern fn(*mut libc::c_uchar, libc::c_int) -> libc::c_int>, 
  cleanup: Option<extern fn()>,
  add: Option<extern fn(*mut libc::c_void, libc::c_int, libc::c_double) -> libc::c_int>,
  pseudorand: Option<extern fn(*mut libc::c_uchar, libc::c_int) -> libc::c_int>, 
  status: Option<extern fn() -> libc::c_int>
}

extern {
  fn ENGINE_get_static_state() -> *mut libc::c_void;
  fn CRYPTO_set_mem_functions(m: *mut libc::c_void, r: *mut libc::c_void, f: *mut libc::c_void) -> libc::c_int;
  fn ENGINE_set_id(e: ENGINE, id: *const libc::c_uchar) -> libc::c_int;
  fn ENGINE_set_name(e: ENGINE, id: *const libc::c_uchar) -> libc::c_int;
  fn ENGINE_set_init_function(e: ENGINE, init_f: extern fn(ENGINE) -> libc::c_int) -> libc::c_int;
  fn ENGINE_set_RSA(e: ENGINE, rsa: RSA_METHOD) -> libc::c_int;
  fn ENGINE_set_RAND(e: ENGINE, rand_meth: *const rand_meth_st) -> libc::c_int;
  fn RSA_get_default_method() -> RSA_METHOD;
  fn RSA_meth_dup(meth: RSA_METHOD) -> RSA_METHOD;
  fn RSA_meth_set1_name(meth: RSA_METHOD, name: *const libc::c_uchar) -> libc::c_int;
  fn RSA_meth_set_flags(meth: RSA_METHOD, flags: libc::c_int) -> libc::c_int;
  fn RSA_meth_set_priv_enc(meth: RSA_METHOD) -> libc::c_int;
  fn RSA_meth_set_priv_dec(meth: RSA_METHOD) -> libc::c_int;
  fn RSA_meth_set_finish(meth: RSA_METHOD) -> libc::c_int;
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
extern fn kms_init(e: ENGINE) -> libc::c_int {
  println!("kms_init");
  return 1;
}

extern fn rand_bytes(buf: *mut libc::c_uchar, num: libc::c_int) -> libc::c_int {
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

extern fn rand_status() -> libc::c_int {
  return 1;
}

// openssl engine entry points
#[no_mangle]
pub extern fn v_check(v: libc::c_ulong) -> libc::c_ulong {
  //println!("v_check {}", v);
  if v >= OSSL_DYNAMIC_OLDEST {
    return OSSL_DYNAMIC_OLDEST;
  }
  return 0;
}

#[no_mangle]
pub extern fn bind_engine(e: ENGINE, _id: *const libc::c_char, fns: *const dynamic_fns) -> libc::c_int {
  //println!("bind_engine");
  unsafe {
    if ENGINE_get_static_state() != (*fns).static_state {
      assert_eq!(CRYPTO_set_mem_functions((*fns).dyn_MEM_malloc_fn, (*fns).dyn_MEM_realloc_fn, (*fns).dyn_MEM_free_fn), 1); 
    }
    assert_eq!(ENGINE_set_id(e, ENGINE_ID.as_ptr()), 1);
    assert_eq!(ENGINE_set_name(e, ENGINE_NAME.as_ptr()), 1);
    assert_eq!(ENGINE_set_init_function(e, kms_init), 1);
    /*
    let ops = RSA_meth_dup(RSA_get_default_method());
    RSA_meth_set1_name(ops, "KMS RSA method\0".as_ptr());
    ENGINE_set_RSA(e, ops);
    */
    assert_eq!(ENGINE_set_RAND(e, &RAND_METH), 1);
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
