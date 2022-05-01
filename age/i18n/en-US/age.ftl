# Copyright 2020 Jack Grigg
#
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

### Localization for strings in the age library crate

-age = age
-rage = rage
-ssh-rsa = ssh-rsa
-ssh-ed25519 = ssh-ed25519

## CLI helpers

cli-secret-input-required = Input is required
cli-secret-input-mismatch = Inputs do not match

cli-passphrase-desc = Type passphrase (leave empty to autogenerate a secure one)
cli-passphrase-prompt = Passphrase
cli-passphrase-confirm = Confirm passphrase

-flag-armor = -a/--armor
-flag-output = -o/--output
-output-stdout = -o -

cli-truncated-tty = truncated; use a pipe, a redirect, or {-flag-output} to decrypt the entire file

err-detected-binary = detected unprintable data; refusing to output to the terminal.
rec-detected-binary = Force with '{-output-stdout}'.

err-deny-binary-output = refusing to output binary to the terminal.
rec-deny-binary-output = Did you mean to use {-flag-armor}? {rec-detected-binary}

## Errors

err-decryption-failed = Decryption failed

err-excessive-work = Excessive work parameter for passphrase.
rec-excessive-work = Decryption would take around {$duration} seconds.

err-header-invalid = Header is invalid

err-header-mac-invalid = Header MAC is invalid

err-key-decryption = Failed to decrypt an encrypted key

err-no-matching-keys = No matching keys found

err-unknown-format = Unknown {-age} format.
rec-unknown-format = Have you tried upgrading to the latest version?

err-missing-plugin = Could not find '{$plugin_name}' on the PATH.
rec-missing-plugin = Have you installed the plugin?

err-plugin-identity = '{$plugin_name}' couldn't use an identity: {$message}
err-plugin-recipient = '{$plugin_name}' couldn't use recipient {$recipient}: {$message}
err-plugin-multiple = Plugin returned multiple errors:

err-read-identity-encrypted-without-passphrase =
    Identity file '{$filename}' is encrypted with {-age} but not with a passphrase.
err-read-identity-not-found = Identity file not found: {$filename}

err-stream-last-chunk-empty = Last STREAM chunk is empty. Please report this, and/or try an older {-rage} version.

## Encrypted identities

encrypted-passphrase-prompt = Type passphrase for encrypted identity '{$filename}'

encrypted-warn-no-match = Warning: encrypted identity file '{$filename}' didn't match file's recipients

## Plugin identities

plugin-waiting-on-binary = Waiting for {$binary_name}...

## SSH identities

ssh-passphrase-prompt = Type passphrase for OpenSSH key '{$filename}'

ssh-unsupported-key = Unsupported SSH key: {$name}

ssh-insecure-key-format =
    Insecure Encrypted Key Format
    -----------------------------
    Prior to OpenSSH version 7.8, if a password was set when generating a new
    DSA, ECDSA, or RSA key, ssh-keygen would encrypt the key using the encrypted
    PEM format. This encryption format is insecure and should no longer be used.

    You can migrate your key to the encrypted SSH private key format (which has
    been supported by OpenSSH since version 6.5, released in January 2014) by
    changing its passphrase with the following command:

    {"    "}{$change_passphrase}

    If you are using an OpenSSH version between 6.5 and 7.7 (such as the default
    OpenSSH provided on Ubuntu 18.04 LTS), you can use the following command to
    force keys to be generated using the new format:

    {"    "}{$gen_new}

ssh-unsupported-cipher =
    Unsupported Cipher for Encrypted SSH Key
    ----------------------------------------
    OpenSSH internally supports several different ciphers for encrypted keys,
    but it has only ever directly generated a few of them. {-rage} supports all
    ciphers that ssh-keygen might generate, and is being updated on a
    case-by-case basis with support for non-standard ciphers. Your key uses a
    currently-unsupported cipher ({$cipher}).

    If you would like support for this key type, please open an issue here:

    {$new_issue}

ssh-unsupported-key-type =
    Unsupported SSH Key Type
    ------------------------
    OpenSSH supports various different key types, but {-rage} only supports a
    subset of these for backwards compatibility, specifically the '{-ssh-rsa}'
    and '{-ssh-ed25519}' key types. This SSH key uses the unsupported key type
    '{$key_type}'.
