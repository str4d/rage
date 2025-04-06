use std::fs;
use std::io::Read;

use age::scrypt;
use age_core::secrecy::SecretString;

#[test]
#[cfg(feature = "cli-common")]
fn age_test_vectors() -> Result<(), Box<dyn std::error::Error>> {
    use age::cli_common::StdinGuard;

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

        let d = age::Decryptor::new(fs::File::open(&path)?)?;
        let res = if !d.is_scrypt() {
            let identities = age::cli_common::read_identities(
                vec![format!(
                    "{}/{}_key.txt",
                    path.parent().unwrap().to_str().unwrap(),
                    name
                )],
                None,
                &mut StdinGuard::new(false),
            )?;
            d.decrypt(identities.iter().map(|i| i.as_ref() as &dyn age::Identity))
        } else {
            let mut passphrase = String::new();
            fs::File::open(format!(
                "{}/{}_password.txt",
                path.parent().unwrap().to_str().unwrap(),
                name
            ))?
            .read_to_string(&mut passphrase)?;
            let passphrase = SecretString::from(passphrase);
            let identity = scrypt::Identity::new(passphrase);
            d.decrypt(Some(&identity as _).into_iter())
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
