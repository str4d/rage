use secrecy::SecretString;
use std::fs;
use std::io::{self, Read};

#[test]
fn age_test_vectors() -> Result<(), age::DecryptError> {
    for test_vector in fs::read_dir("./tests/testdata")?.filter(|res| {
        res.as_ref()
            .map(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "age")
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    }) {
        let test_vector = test_vector?;
        let path = test_vector.path();
        let name = path.file_stem().unwrap().to_str().unwrap();
        let expect_failure = name.starts_with("fail_");

        let res = match age::Decryptor::new(fs::File::open(&path)?)? {
            age::Decryptor::Recipients(d) => {
                let identities = age::cli_common::read_identities(
                    vec![format!(
                        "{}/{}_key.txt",
                        path.parent().unwrap().to_str().unwrap(),
                        name
                    )],
                    |e| age::DecryptError::Io(io::Error::new(io::ErrorKind::NotFound, e)),
                    |_, _| age::DecryptError::DecryptionFailed,
                )?;
                d.decrypt(identities.iter().map(|i| i.as_ref() as &dyn age::Identity))
            }
            age::Decryptor::Passphrase(d) => {
                let mut passphrase = String::new();
                fs::File::open(format!(
                    "{}/{}_password.txt",
                    path.parent().unwrap().to_str().unwrap(),
                    name
                ))?
                .read_to_string(&mut passphrase)?;
                let passphrase = SecretString::new(passphrase);
                d.decrypt(&passphrase, None)
            }
        };

        match (res, expect_failure) {
            (Ok(mut r), false) => {
                // Check that we can read the entire file.
                let mut buf = vec![];
                r.read_to_end(&mut buf)?;
            }
            (Ok(_), true) => panic!("Test vector {} did not fail as expected", name),
            (Err(e), false) => panic!("Test vector {} failed unexpectedly: {:?}", name, e),
            (Err(_), true) => (),
        }
    }

    Ok(())
}
