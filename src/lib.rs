use std::collections::HashMap;
use chacha20poly1305::{aead::{Aead, OsRng}, AeadCore, ChaCha20Poly1305, Error, Key, KeyInit, Nonce};
use sha2::Sha256;
use pbkdf2::pbkdf2_hmac_array;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[derive(Debug, Eq, Hash, PartialEq)]
struct KeystoreIndex(String);

#[derive(Debug, PartialEq)]
struct KeystoreEntryMeta {
    nonce: Nonce,
    round: u32,
}

#[derive(Debug, PartialEq)]
struct KeystoreEntry<T> {
    public: T,
    private: Vec<u8>,
    meta: KeystoreEntryMeta,
}

pub struct Keystore<T> {
    entries: HashMap<KeystoreIndex, KeystoreEntry<T>>,
    round: u32,
}

impl<T: Clone> Keystore<T> {
    pub fn new(round: Option<u32>) -> Self {
        Self {
            entries: HashMap::<KeystoreIndex, KeystoreEntry<T>>::new(),
            round: round.unwrap_or(10_000),
        }
    }

    pub fn insert_entry(&mut self, index: String, public_entry: T, private_entry: Vec<u8>, password: String) -> Result<(), Error> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let key = pbkdf2_hmac_array::<Sha256, 32>(&password.into_bytes(), &nonce, self.round);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
        match cipher.encrypt(&nonce, private_entry.as_ref()) {
            Ok(ciphertext) => {
                self.entries.insert(KeystoreIndex(index), KeystoreEntry {
                    public: public_entry,
                    private: ciphertext,
                    meta: KeystoreEntryMeta { nonce, round: self.round },
                });
                Ok(())
            }
            Err(err) => Err(err)
        }
    }

    pub fn get_entry_public(&self, index: String) -> Option<T> {
        match self.entries.get(&KeystoreIndex(index)) {
            None => None,
            Some(e) => Some(e.public.clone()),
        }
    }

    pub fn get_entry_private(&self, index: String, password: String) -> Option<Result<Vec<u8>, Error>> {
        match self.entries.get(&KeystoreIndex(index)) {
            None => None,
            Some(e) => {
                let nonce = e.meta.nonce;
                let key = pbkdf2_hmac_array::<Sha256, 32>(&password.into_bytes(), &nonce, e.meta.round);
                let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
                match cipher.decrypt(&nonce, e.private.as_ref()) {
                    Ok(plaintext) => Some(Ok(plaintext)),
                    Err(err) => Some(Err(err))
                }
            }
        }
    }

    pub fn update_entry(&mut self, index: String, old_password: String, public_entry: T, private_entry: Vec<u8>, new_password: String) -> Option<Result<(), Error>> {
        match self.remove_entry(index.clone(), old_password) {
            None => None,
            Some(Err(e)) => Some(Err(e)),
            Some(Ok(_)) => Some(self.insert_entry(index, public_entry, private_entry, new_password)),
        }
    }

    pub fn remove_entry(&mut self, index: String, password: String) -> Option<Result<(), Error>> {
        match self.get_entry_private(index.clone(), password) {
            None => None,
            Some(Err(e)) => Some(Err(e)),
            Some(Ok(_)) => {
                self.entries.remove(&KeystoreIndex(index));
                Some(Ok(()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn respond_none_with_a_missing_index() {
        let keystore = Keystore::<String>::new(None);

        assert_eq!(keystore.get_entry_public("index".to_string()), None);
        assert_eq!(keystore.get_entry_private("index".to_string(), "password".to_string()), None);
    }

    #[test]
    fn add_an_entry() {
        let mut keystore = Keystore::<String>::new(None);

        assert_eq!(keystore.insert_entry("index".to_string(), "public".to_string(), "private".as_bytes().to_vec(), "password".to_string()), Ok(()));
        assert_eq!(keystore.entries.get(&KeystoreIndex("index".to_string())).unwrap().public, "public".to_string());
        assert_ne!(keystore.entries.get(&KeystoreIndex("index".to_string())).unwrap().private, "private".as_bytes().to_vec());
    }

    #[test]
    fn find_an_entry_from_its_index() {
        let mut keystore = Keystore::<String>::new(None);
        keystore.entries.insert(KeystoreIndex("index".to_string()), KeystoreEntry {
            public: "public".to_string(),
            private : vec![221, 196, 210, 224, 17, 74, 123, 140, 86, 222, 90, 16, 186, 177, 27, 47, 233, 66, 102, 228, 104, 227, 55],
            meta: KeystoreEntryMeta {
                nonce: Nonce::from_slice(&[78, 63, 137, 212, 148, 220, 165, 63, 239, 82, 130, 169]).clone(),
                round: 10_000,
            },
        });

        assert_eq!(keystore.get_entry_public("index".to_string()), Some("public".to_string()));
        assert_eq!(keystore.get_entry_private("index".to_string(), "password".to_string()), Some(Ok("private".as_bytes().to_vec())));
    }

    #[test]
    fn update_an_entry_from_its_index() {
        let mut keystore = Keystore::<String>::new(None);
        keystore.entries.insert(KeystoreIndex("index".to_string()), KeystoreEntry {
            public: "public".to_string(),
            private : vec![221, 196, 210, 224, 17, 74, 123, 140, 86, 222, 90, 16, 186, 177, 27, 47, 233, 66, 102, 228, 104, 227, 55],
            meta: KeystoreEntryMeta {
                nonce: Nonce::from_slice(&[78, 63, 137, 212, 148, 220, 165, 63, 239, 82, 130, 169]).clone(),
                round: 10_000,
            },
        });

        assert_eq!(keystore.update_entry("index".to_string(), "password".to_string(), "new_public".to_string(), "new_private".as_bytes().to_vec(), "new_password".to_string()), Some(Ok(())));
        assert_eq!(keystore.entries.get(&KeystoreIndex("index".to_string())).unwrap().public, "new_public".to_string());
        assert_ne!(keystore.entries.get(&KeystoreIndex("index".to_string())).unwrap().private, "new_private".as_bytes().to_vec());
    }

    #[test]
    fn remove_an_entry_from_its_index() {
        let mut keystore = Keystore::<String>::new(None);
        keystore.entries.insert(KeystoreIndex("index".to_string()), KeystoreEntry {
            public: "public".to_string(),
            private : vec![221, 196, 210, 224, 17, 74, 123, 140, 86, 222, 90, 16, 186, 177, 27, 47, 233, 66, 102, 228, 104, 227, 55],
            meta: KeystoreEntryMeta {
                nonce: Nonce::from_slice(&[78, 63, 137, 212, 148, 220, 165, 63, 239, 82, 130, 169]).clone(),
                round: 10_000,
            },
        });

        keystore.remove_entry("index".to_string(), "password".to_string());

        assert_eq!(keystore.entries.get(&KeystoreIndex("index".to_string())), None);
    }

    #[test]
    fn fail_to_decrypt() {
        let mut keystore = Keystore::<String>::new(None);
        keystore.entries.insert(KeystoreIndex("index".to_string()), KeystoreEntry {
            public: "public".to_string(),
            private : vec![221, 196, 210, 224, 17, 74, 123, 140, 86, 222, 90, 16, 186, 177, 27, 47, 233, 66, 102, 228, 104, 227, 55],
            meta: KeystoreEntryMeta {
                nonce: Nonce::from_slice(&[78, 63, 137, 212, 148, 220, 165, 63, 239, 82, 130, 169]).clone(),
                round: 10_000,
            },
        });

        assert!(keystore.get_entry_private("index".to_string(), "wrong_password".to_string()).unwrap().is_err());
        assert!(keystore.remove_entry("index".to_string(), "wrong_password".to_string()).unwrap().is_err());
        assert!(keystore.update_entry("index".to_string(), "wrong_password".to_string(), "new_public".to_string(), "new_private".as_bytes().to_vec(), "new_password".to_string()).unwrap().is_err());
    }

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
