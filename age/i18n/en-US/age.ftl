# Copyright 2020 Jack Grigg
#
# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

### Localization for strings in the age library crate

## Terms (not to be localized)

-age = age
-rage = rage

-scrypt-recipient = scrypt::Recipient

-openssh = OpenSSH
-ssh-keygen = ssh-keygen
-ssh-rsa = ssh-rsa
-ssh-ed25519 = ssh-ed25519
-fido-u2f = FIDO/U2F
-yubikeys = YubiKeys
-piv = PIV

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

err-deny-overwrite-file = refusing to overwrite existing file '{$filename}'.

err-invalid-filename = invalid filename '{$filename}'.

err-missing-directory = directory '{$path}' does not exist.

## Identity file errors

err-failed-to-write-output = Failed to write to output: {$err}

err-identity-file-contains-plugin = Identity file '{$filename}' contains identities for '{-age-plugin-}{$plugin_name}'.
rec-identity-file-contains-plugin = Try using '{-age-plugin-}{$plugin_name}' to convert this identity to a recipient.

err-no-identities-in-file = No identities found in file '{$filename}'.
err-no-identities-in-stdin = No identities found in standard input.

## Errors

err-decryption-failed = Decryption failed

err-excessive-work = Excessive work parameter for passphrase.
rec-excessive-work = Decryption would take around {$duration} seconds.

err-header-invalid = Header is invalid

err-header-mac-invalid = Header MAC is invalid

err-incompatible-recipients-oneway = Cannot encrypt to a recipient with labels '{$labels}' alongside a recipient with no labels
err-incompatible-recipients-twoway = Cannot encrypt to a recipient with labels '{$left}' alongside a recipient with labels '{$right}'

err-invalid-recipient-labels = The first recipient requires one or more invalid labels: '{$labels}'

err-key-decryption = Failed to decrypt an encrypted key

err-missing-recipients = Missing recipients.

err-mixed-recipient-passphrase = {-scrypt-recipient} can't be used with other recipients.

err-no-matching-keys = No matching keys found

err-unknown-format = Unknown {-age} format.
rec-unknown-format = Have you tried upgrading to the latest version?

err-missing-plugin = Could not find '{$plugin_name}' on the PATH.
rec-missing-plugin = Have you installed the plugin?

err-plugin-identity = '{$plugin_name}' couldn't use an identity: {$message}
err-plugin-recipient = '{$plugin_name}' couldn't use recipient {$recipient}: {$message}

err-plugin-died = '{$plugin_name}' unexpectedly died.
rec-plugin-died-1 = If you are developing a plugin, run with {$env_var} for more information.
rec-plugin-died-2 = Warning: this prints private encryption key material to standard error.

err-plugin-multiple = Plugin returned multiple errors:

err-read-identity-encrypted-without-passphrase =
    Identity file '{$filename}' is encrypted with {-age} but not with a passphrase.
err-read-identity-not-found = Identity file not found: {$filename}

err-read-invalid-recipient = Invalid recipient '{$recipient}'.

err-read-invalid-recipients-file =
    Recipients file '{$filename}' contains non-recipient data on line {$line_number}.

err-read-missing-recipients-file = Recipients file not found: {$filename}

err-read-multiple-stdin = Standard input can't be used for multiple purposes.

err-read-rsa-modulus-too-large =
    RSA Modulus Too Large
    ---------------------
    {-openssh} supports various RSA modulus sizes, but {-rage} only supports public
    keys of at most {$max_size} bits, to prevent a Denial of Service (DoS) condition
    when encrypting to untrusted public keys.

err-read-rsa-modulus-too-small = RSA key size is too small.

err-stream-last-chunk-empty = Last STREAM chunk is empty. Please report this, and/or try an older {-rage} version.

## Encrypted identities

encrypted-passphrase-prompt = Type passphrase for encrypted identity '{$filename}'

encrypted-warn-no-match = Warning: encrypted identity file '{$filename}' didn't match file's recipients

## Plugin identities

plugin-waiting-on-binary = Waiting for {$binary_name}...

## SSH identities

ssh-passphrase-prompt = Type passphrase for {-openssh} key '{$filename}'

ssh-unsupported-key = Unsupported SSH key: {$name}

ssh-insecure-key-format =
    Insecure Encrypted Key Format
    -----------------------------
    Prior to {-openssh} version 7.8, if a password was set when generating a new
    DSA, ECDSA, or RSA key, {-ssh-keygen} would encrypt the key using the encrypted
    PEM format. This encryption format is insecure and should no longer be used.

    You can migrate your key to the encrypted SSH private key format (which has
    been supported by {-openssh} since version 6.5, released in January 2014) by
    changing its passphrase with the following command:

    {"    "}{$change_passphrase}

    If you are using an {-openssh} version between 6.5 and 7.7 (such as the default
    {-openssh} provided on Ubuntu 18.04 LTS), you can use the following command to
    force keys to be generated using the new format:

    {"    "}{$gen_new}

ssh-unsupported-cipher =
    Unsupported Cipher for Encrypted SSH Key
    ----------------------------------------
    {-openssh} internally supports several different ciphers for encrypted keys,
    but it has only ever directly generated a few of them. {-rage} supports all
    ciphers that {-ssh-keygen} might generate, and is being updated on a
    case-by-case basis with support for non-standard ciphers. Your key uses a
    currently-unsupported cipher ({$cipher}).

    If you would like support for this key type, please open an issue here:

    {$new_issue}

ssh-unsupported-key-type =
    Unsupported SSH Key Type
    ------------------------
    {-openssh} supports various different key types, but {-rage} only supports a
    subset of these for backwards compatibility, specifically the '{-ssh-rsa}'
    and '{-ssh-ed25519}' key types. This SSH key uses the unsupported key type
    '{$key_type}'.

ssh-unsupported-security-key =
    Unsupported SSH Hardware Authenticator
    --------------------------------------
    {-openssh} version 8.2p1 added support for {-fido-u2f} hardware authenticators,
    including hardware security keys such as {-yubikeys}. {-rage} does not work with
    these SSH key types, because their protocol does not support encryption.
    This SSH key uses the incompatible type '{$key_type}'.

    If you have a compatible hardware security key, you should use this plugin:

    {$age_plugin_yubikey_url}

    A hardware security key used with both {-openssh} and this plugin will have a
    separate SSH public key and {-age} encryption recipient, because the plugin
    implements the {-piv} protocol.
