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

cli-secret-input-required = Entrée requise
cli-secret-input-mismatch = Les entrées ne correspondent pas

cli-passphrase-desc = Tapez votre phrase secrète (laissez vide pour en générer une très sure automatiquement)
cli-passphrase-prompt = Phrase secrète
cli-passphrase-confirm = Confirmez votre phrase secrète

-flag-armor = -a/--armor
-flag-output = -o/--output
-output-stdout = -o -

cli-truncated-tty = tronqué; utilisez un pipe, une redirection ou {-flag-output} pour déchiffrer l'entièreté du fichier

err-detected-binary = données non impressibles détectées; par précaution, pas d'impression dans le terminal.
rec-detected-binary = Forcez l'impression avec '{-output-stdout}'.

err-deny-binary-output = refus d'impression de valeurs binaires dans le terminal.
rec-deny-binary-output = Est-ce que vous vouliez utiliser {-flag-armor}? {rec-detected-binary}

err-deny-overwrite-file = refus d'écraser le fichier existant '{$filename}'.

## Identity file errors

err-failed-to-write-output = Echec d'écriture vers la sortie: {$err}

err-identity-file-contains-plugin = Le ficher d'identité '{$filename}' contient des identités pour '{-age-plugin-}{$plugin_name}'.
rec-identity-file-contains-plugin = Essayez d'utiliser {-age-plugin-}{$plugin_name}' pour convertir cette identité en un destinataire.

err-no-identities-in-file = Aucune identité trouvée dans le fichier '{$filename}'.
err-no-identities-in-stdin = Aucune identité trouvée dans l'entrée standard (stdin).

## Errors

err-decryption-failed = Echec du déchiffrement

err-excessive-work = Facteur d'effort trop grand pour la phrase secrète.
rec-excessive-work = Le déchiffrement prendrait environ {$duration} seconds.

err-header-invalid = En-tête non valable

err-header-mac-invalid = Le MAC de l'en-tête est invalide

err-key-decryption = Echec du déchiffrement d'une clef chiffrée

err-no-matching-keys = Aucune clef correspondante n'a été trouvée

err-unknown-format = Format {-age} inconnu.
rec-unknown-format = Avez-vous tenté de mettre jour vers la dernière version ?

err-missing-plugin = Impossible de trouver '{$plugin_name}' dans le PATH.
rec-missing-plugin = Avez-vous installé le plugin ?

err-plugin-identity = '{$plugin_name}' n'a pas pu utiliser une identité: {$message}
err-plugin-recipient = '{$plugin_name}' n'a pas pu utiliser le destinataire {$recipient}: {$message}

err-plugin-died = '{$plugin_name}' est mort de manière inopinée.
rec-plugin-died-1 = Si vous développez un plugin, utilisez {$env_var} pour plus d'informations.
rec-plugin-died-2 = Attention: ceci imprime des informations de clef privées sur la sortie d'erreur standard.

err-plugin-multiple = Le plugin a retourné de multiples erreurs:

err-read-identity-encrypted-without-passphrase =
    Le fichier d'identité '{$filename}' est chiffré avec {-age} mais pas avec une phrase secrète.
err-read-identity-not-found = Fichier d'identité introuvable: {$filename}

err-read-invalid-recipient = Destinataire invalide: '{$recipient}'.

err-read-invalid-recipients-file =
    Le fichier de destinataires '{$filename}' contient des données autres que des destinataires à la ligne {$line_number}.

err-read-missing-recipients-file = Fichier de destinataires introuvable: {$filename}

err-read-multiple-stdin = L'entrée standard (stdin) ne peut pas être utilisée pour plus d'une chose.

err-read-rsa-modulus-too-large =
    Module RSA Trop Grand
    ---------------------
    {-openssh} supporte de nombreuses tailles de modules RSA, mais {-rage} ne supporte que des clefs
    publiques d'au plus {$max_size} bits, pour éviter les risques de déni de service (DoS) lors du
    chiffrement vers des clefs publiques inconnues.

err-read-rsa-modulus-too-small = Taille de clef RSA trop petite.

err-stream-last-chunk-empty = Le dernier morceau du STREAM est vide. chunk is empty. S'il vous plait, faites un bug report, et/ou essayez avec une version plus ancienne de {-rage}.

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
    Authenficateur physique SSH non supporté
    --------------------------------------
    {-openssh} version 8.2p1 a ajouté le support pour les authentificateurs physique {-fido-u2f}
    y compris les clefs de sécurité physiques telles que {-yubikeys}. {-rage} ne fonctionne pas
    avec ce type de clef SSH, parcque leur protocole ne supporte pas le chiffrement.
    Cette clef SSH est du type '{$key_type}' qui n'est pas compatible.

    Si vous avez une clef de sécurité physique, vous devriez utiliser ce plugin:

    {$age_plugin_yubikey_url}

    Une clef de sécurité utilisée avec à la fois {-openssh} et ce plugin aura
    une clef SSH publique différente de sa clef destinataire {-age}, car ce plugin
    implémente le protocol {-piv}.
