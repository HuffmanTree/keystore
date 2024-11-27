use std::collections::HashMap;
use chacha20poly1305::{aead::{Aead, OsRng}, AeadCore, ChaCha20Poly1305, Error, Key, KeyInit, Nonce};
use sha2::Sha256;
use pbkdf2::pbkdf2_hmac_array;

pub fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[derive(Debug, Eq, Hash, PartialEq)]
pub struct KeystoreIndex(String);

#[derive(Debug, PartialEq)]
struct KeystoreEntryMeta {
    nonce: Nonce,
    round: u32,
}

#[derive(Debug, PartialEq)]
pub struct KeystoreEntry<T> {
    public: T,
    private: Vec<u8>,
    meta: KeystoreEntryMeta,
}

type KeystoreEntries<T> = HashMap<KeystoreIndex, KeystoreEntry<T>>;
type KeystoreFn<T> = fn(e: &KeystoreEntries<T>) -> Result<(), Error>;

pub struct Keystore<T> {
    entries: KeystoreEntries<T>,
    round: u32,
    synced: bool,
    save_entries: KeystoreFn<T>,
}

impl<T: Clone> Keystore<T> {
    pub fn new(save: KeystoreFn<T>, initial: Option<KeystoreEntries<T>>, round: Option<u32>) -> Self {
        Self {
            entries: initial.unwrap_or_default(),
            round: round.unwrap_or(10_000),
            synced: false,
            save_entries: save,
        }
    }

    pub fn save(&mut self) -> Result<(), Error> {
        if self.synced {
            Ok(())
        } else {
            match (self.save_entries)(&self.entries) {
                Ok(_) => { self.synced = true; Ok(()) },
                Err(e) => Err(e),
            }
        }
    }

    fn upsert_entry(&mut self, index: String, public_entry: T, private_entry: Vec<u8>, password: String) -> Result<(), Error> {
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
                self.synced = false;
                Ok(())
            }
            Err(err) => Err(err),
        }
    }

    pub fn insert_entry(&mut self, index: String, public_entry: T, private_entry: Vec<u8>, password: String) -> Option<Result<(), Error>> {
        match self.entries.get(&KeystoreIndex(index.clone())) {
            Some(_) => None,
            None => Some(self.upsert_entry(index, public_entry, private_entry, password)),
        }
    }

    pub fn get_entry_public(&self, index: String) -> Option<T> {
        self.entries.get(&KeystoreIndex(index)).map(|e| e.public.clone())
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

    pub fn update_entry(&mut self, index: String, old_password: String, public_entry: T, private_entry: Vec<u8>, new_password: Option<String>) -> Option<Result<(), Error>> {
        match self.get_entry_private(index.clone(), old_password.clone()) {
            None => None,
            Some(Err(e)) => Some(Err(e)),
            Some(Ok(_)) => Some(self.upsert_entry(index, public_entry, private_entry, new_password.unwrap_or(old_password))),
        }
    }

    pub fn remove_entry(&mut self, index: String, password: String) -> Option<Result<(), Error>> {
        match self.get_entry_private(index.clone(), password) {
            None => None,
            Some(Err(e)) => Some(Err(e)),
            Some(Ok(_)) => {
                self.entries.remove(&KeystoreIndex(index));
                self.synced = false;
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
        fn save(_e: &KeystoreEntries<String>) -> Result<(), Error> { Ok(()) }
        let keystore = Keystore::<String>::new(save, None, None);

        assert_eq!(keystore.get_entry_public("index".to_string()), None);
        assert_eq!(keystore.get_entry_private("index".to_string(), "password".to_string()), None);
    }

    #[test]
    fn save_keystore_success() {
        fn save(_e: &KeystoreEntries<String>) -> Result<(), Error> {
            Ok(())
        }
        let mut keystore = Keystore::<String>::new(save, None, None);

        assert!(!keystore.synced);
        assert!(keystore.save().is_ok());
        assert!(keystore.synced);
    }

    #[test]
    fn save_keystore_fail() {
        fn save(_e: &KeystoreEntries<String>) -> Result<(), Error> {
            Err(Error {})
        }
        let mut keystore = Keystore::<String>::new(save, None, None);

        assert!(!keystore.synced);
        assert!(keystore.save().is_err());
        assert!(!keystore.synced);
    }

    #[test]
    fn add_an_entry() {
        fn save(_e: &KeystoreEntries<String>) -> Result<(), Error> { Ok(()) }
        let mut keystore = Keystore::<String>::new(save, None, None);
        keystore.synced = true;

        assert_eq!(keystore.insert_entry("index".to_string(), "public".to_string(), "private".as_bytes().to_vec(), "password".to_string()), Some(Ok(())));
        assert!(!keystore.synced);
        assert_eq!(keystore.insert_entry("index".to_string(), "new_public".to_string(), "private".as_bytes().to_vec(), "password".to_string()), None);
        assert_eq!(keystore.entries.get(&KeystoreIndex("index".to_string())).unwrap().public, "public".to_string());
        assert_ne!(keystore.entries.get(&KeystoreIndex("index".to_string())).unwrap().private, "private".as_bytes().to_vec());
    }

    #[test]
    fn find_an_entry_from_its_index() {
        fn save(_e: &KeystoreEntries<String>) -> Result<(), Error> { Ok(()) }
        let mut keystore = Keystore::<String>::new(save, None, None);
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
        fn save(_e: &KeystoreEntries<String>) -> Result<(), Error> { Ok(()) }
        let mut keystore = Keystore::<String>::new(save, None, None);
        keystore.entries.insert(KeystoreIndex("index".to_string()), KeystoreEntry {
            public: "public".to_string(),
            private : vec![221, 196, 210, 224, 17, 74, 123, 140, 86, 222, 90, 16, 186, 177, 27, 47, 233, 66, 102, 228, 104, 227, 55],
            meta: KeystoreEntryMeta {
                nonce: Nonce::from_slice(&[78, 63, 137, 212, 148, 220, 165, 63, 239, 82, 130, 169]).clone(),
                round: 10_000,
            },
        });
        keystore.synced = true;

        assert_eq!(keystore.update_entry("index".to_string(), "password".to_string(), "new_public".to_string(), "new_private".as_bytes().to_vec(), Some("new_password".to_string())), Some(Ok(())));
        assert!(!keystore.synced);
        assert_eq!(keystore.entries.get(&KeystoreIndex("index".to_string())).unwrap().public, "new_public".to_string());
        assert_ne!(keystore.entries.get(&KeystoreIndex("index".to_string())).unwrap().private, "new_private".as_bytes().to_vec());
    }

    #[test]
    fn remove_an_entry_from_its_index() {
        fn save(_e: &KeystoreEntries<String>) -> Result<(), Error> { Ok(()) }
        let mut keystore = Keystore::<String>::new(save, None, None);
        keystore.entries.insert(KeystoreIndex("index".to_string()), KeystoreEntry {
            public: "public".to_string(),
            private : vec![221, 196, 210, 224, 17, 74, 123, 140, 86, 222, 90, 16, 186, 177, 27, 47, 233, 66, 102, 228, 104, 227, 55],
            meta: KeystoreEntryMeta {
                nonce: Nonce::from_slice(&[78, 63, 137, 212, 148, 220, 165, 63, 239, 82, 130, 169]).clone(),
                round: 10_000,
            },
        });
        keystore.synced = true;

        keystore.remove_entry("index".to_string(), "password".to_string());

        assert_eq!(keystore.entries.get(&KeystoreIndex("index".to_string())), None);
        assert!(!keystore.synced);
    }

    #[test]
    fn fail_to_decrypt() {
        fn save(_e: &KeystoreEntries<String>) -> Result<(), Error> { Ok(()) }
        let mut keystore = Keystore::<String>::new(save, None, None);
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
        assert!(keystore.update_entry("index".to_string(), "wrong_password".to_string(), "new_public".to_string(), "new_private".as_bytes().to_vec(), Some("new_password".to_string())).unwrap().is_err());
    }

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
