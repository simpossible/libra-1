
use std::os::raw::{c_char};
use std::ffi::{CString};
use std::io::Bytes;
use std::fmt::Error;
use libra_wallet::mnemonic::{U11BitWriter,WORDS};
use std::{convert::TryFrom, ops::AddAssign};
use byteorder::{ByteOrder, LittleEndian};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;
use hex;
use std::ffi::CStr;
use crypto::{hmac::Hmac as CryptoHmac, pbkdf2::pbkdf2, sha3::Sha3};
use libra_crypto::{ed25519::*, hash::HashValue, hkdf::Hkdf, traits::SigningKey};
//use types::account_address::AccountAddress;
//use bytes::{BytesMut, BufMut, BigEndian};
//https://www.greyblake.com/blog/2017-08-10-exposing-rust-library-to-c/

#[repr(C)]
pub struct RustBuffer {
    data: * mut u8,
    len: u32,

}

impl RustBuffer {

}

#[no_mangle]
//extern fn generate_data(datainfo:Vec<u8>,datalen:u32) -> RustBuffer {
//    let mut buf = vec![0; 512].into_boxed_slice();
//    let mut buf = data.into
//    let mut buf = data.into_boxed_slice();


//    let mut buf = datainfo.into_boxed_slice();
//    let buf = buf.as_mut_ptr();
//    std::mem::forget(buf);
//
//    RustBuffer { data:buf, len:datalen }


//}

#[no_mangle]
extern "C" fn free_rust_buf(buf: RustBuffer) {
    let s = unsafe { std::slice::from_raw_parts_mut(buf.data, buf.len as usize) };
    let s = s.as_mut_ptr();
    unsafe {
        Box::from_raw(s);
    }
}

#[no_mangle]
pub extern fn say_hello() -> *mut c_char {
    CString::new("Hello Rust").unwrap().into_raw()
}

pub fn vec_from_str(s:&str) -> Result<Vec<&str>,u8> {
    let words: Vec<_> = s.split(' ').collect();
    let len = words.len();
    if len < 12 || len > 24 || len % 3 != 0 {
        return Err(1);
    }

    let mut mnemonic1 = Vec::with_capacity(words.len());
    let mut bit_writer = U11BitWriter::new(len);
    for word in &words {
        if let Ok(idx) = WORDS.binary_search(word) {
            mnemonic1.push(WORDS[idx]);
            bit_writer.write_u11(idx as u16);
        } else {
            return Err(1);
        }
    }
    // Write any remaining bits.
    bit_writer.write_buffer();

    // This will never fail as we've already checked the word-list is not empty.
    let (checksum, entropy) = bit_writer.bytes.split_last().unwrap();
    let computed_checksum = Sha256::digest(entropy).as_ref()[0] >> (8 - len / 3);
    // Checksum validation.
    if *checksum != computed_checksum {
        return Err(2);
    }
    Ok(mnemonic1)
}

#[no_mangle]
pub extern fn seed_from_m_s<'a>(mnemonic_ptr:*const c_char,salt_ptr:*const c_char,length_ptr:&mut u8) -> * mut u8 {

   let  salt_prefix: &[u8] = b"LIBRA WALLET: mnemonic salt prefix$";
    let bytes =  "sdsd".as_bytes();

    let mstr = unsafe { CStr::from_ptr(mnemonic_ptr) };
    let mnestr = mstr.to_str();
    let mnestr = match mnestr {
        Ok(aa)=>aa,
        Err(err) =>{
            panic!("error mnmonic");
        }
    };
    //第一步 拿到助记词 转化来的string
    let mnevec =  vec_from_str(mnestr);
    let mnevec = match mnevec { Ok(n) => n,Err(e)=>{ panic!("mnemonic error") }};
    let mnevec_slice = mnevec.as_slice().join(" ");

    //第二部 获得盐
    let saltStr = unsafe{CStr::from_ptr(salt_ptr)};
    let salt_str = saltStr.to_str();
    let salt_str = match salt_str { Ok(s) =>s,Err(e)=>{ &""} };


    //第二步 处理盐
    let mut mac = CryptoHmac::new(Sha3::sha3_256(), mnevec_slice.as_bytes());
    let mut output = [0u8; 32];

    let ass = &output;
    let mut msalt = salt_prefix.to_vec();
    msalt.extend_from_slice(salt_str.as_bytes());

    pbkdf2(&mut mac, &msalt, 2048, &mut output);

    println!("the data is {:?}",output);

//    let mut buf = Box::new(output);

    *length_ptr = 32;

    let a = Box::into_raw(Box::new(output));
    let mut a_str = a as *mut u8;


    return a_str;
//    return generate_data(op,32);
}


unsafe fn make_slice<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
    // place pointer address and length in contiguous memory
    let x: [usize; 2] = [ptr as usize, len];

    // cast pointer to array as pointer to slice
    let slice_ptr = &x as * const _ as *const &[u8];

    // dereference pointer to slice, so we get a slice
    *slice_ptr
}

#[no_mangle]
pub extern fn rust_hkdf(first_ptr:*const u8,firstLen:usize,second_ptr:*mut u8,secondLen:usize,length_ptr:&mut u8) -> *mut u8 {
    let mut seed = [0u8,32];


    let f_p = unsafe{ make_slice(first_ptr,firstLen)};
    let s_p =unsafe { make_slice(second_ptr,secondLen)};

    let hkdf_r = Hkdf::<Sha3_256>::extract(Some(f_p), s_p);
    let hkdf_r = match hkdf_r { Ok(a) => a,_=>{panic!("")} };

    println!("f_p  is {:?}",hkdf_r);

    let mut newArray = [0u8;32];
//    for i in 0..32  {
//        newArray[i] = hkdf_r[i];
//    }

    newArray.copy_from_slice(hkdf_r.as_slice());


    *length_ptr = 32;
    let boxa = Box::into_raw(Box::new(newArray));
    let pt = boxa as * mut u8;
    return pt;



//    pub const MASTER_KEY_SALT: &'static [u8] = b"LIBRA WALLET: master key salt$";
//

}

#[no_mangle]
pub extern fn rust_hkdf_privateKey(masterData_ptr:* const u8,masterLen:usize,index:u64,resultLen_ptr:&mut u32) -> *mut u8 {

     let preFix :& [u8] = b"LIBRA WALLET: derived key$";

    let m_p = unsafe{ make_slice(masterData_ptr,masterLen)};

    let mut le_n = [0u8; 8];
    LittleEndian::write_u64(&mut le_n, index);
    let mut info =preFix.to_vec();
    info.extend_from_slice(&le_n);


    let hkdf_expand = Hkdf::<Sha3_256>::expand(m_p, Some(&info), 32);
    let hkdf_expand = match hkdf_expand {Ok(a)=>a,_=>{panic!("error")}};
    let sk = Ed25519PrivateKey::try_from(hkdf_expand.as_slice())
        .expect("Unable to convert into private key");
    let key = sk.to_bytes();
    println!("the sk is {:?}",key);

    let mut cp = [0u8;32];
    cp.copy_from_slice(&key);

    *resultLen_ptr = 32;

    let boxa = Box::into_raw(Box::new(cp));
    let pt = boxa as * mut u8;
    return pt;
}

#[no_mangle]
pub extern fn pubkey_from_private(privateData_ptr:*const u8,privateLen:usize,resultLen_ptr:&mut u8) -> *mut u8 {
    let p_p = unsafe{ make_slice(privateData_ptr,privateLen)};
    let privateKey = Ed25519PrivateKey::try_from(p_p);
    let pk = match privateKey { Ok(p) =>p,_=>{panic!("no")} };

    let pubkey:Ed25519PublicKey = (&pk).into();
    let pubSlice = pubkey.to_bytes();
    println!("pub key is {:?}",pubSlice);


//    let mut a = [0u8;32];
//    a.copy_from_slice(&pubSlice);
    *resultLen_ptr = 32;
    let boxa = Box::into_raw(Box::new(pubSlice));
    let pt = boxa as * mut u8;
    return pt;

}

#[no_mangle]
pub extern fn getAccountAddr(pubData_ptr:*const u8,pubLen:usize,resultLen_ptr:&mut u8)-> * mut u8 {
    let p_p = unsafe{ make_slice(pubData_ptr,pubLen)};
    let hash = *HashValue::from_sha3_256(p_p).as_ref();
    *resultLen_ptr = 32;
//    let addr = AccountAddress::try_from(&hash[..]);
//    let addr = match addr  { Ok(a)=>a,Err(e)=>{AccountAddress::new([0u8;32])} };

    let boxa = Box::into_raw(Box::new(hash));
    let pt = boxa as * mut u8;
    return pt;
}