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

cli-secret-input-required = È richiesto un input
cli-secret-input-mismatch = Gli input non corrispondono

cli-passphrase-desc = Digita la passphrase (lascia vuoto per generarne una sicura automaticamente)
cli-passphrase-prompt = Passphrase
cli-passphrase-confirm = Conferma la passphrase

-flag-armor = -a/--armor
-flag-output = -o/--output
-output-stdout = -o -

cli-truncated-tty = troncato; usa una pipe, una redirezione, o {-flag-output} per decifrare l'intero file

err-detected-binary = rilevati dati non stampabili; rifiuto l'invio dell'output al terminale.
rec-detected-binary = Puoi forzarlo con '{-output-stdout}'.

err-deny-binary-output = rifiuto l'invio di output binario al terminale.
rec-deny-binary-output = Intendevi usare {-flag-armor}? {rec-detected-binary}

## Errors

err-decryption-failed = Decifrazione fallita

err-excessive-work = Parametro di lavoro per la passphrase troppo elevato.
rec-excessive-work = La decifrazione impiegherà circa {$duration} secondi.

err-header-invalid = L'header è invalido

err-header-mac-invalid = Il MAC dell'header è invalido

err-key-decryption = La decifrazione di una chiave crittografata è fallita

err-no-matching-keys = Nessuna chiave corrispondente trovata

err-unknown-format = Formato {-age} sconosciuto.
rec-unknown-format = Hai provato ad aggiornare all'ultima versione?

err-missing-plugin = '{$plugin_name}' non trovato nella PATH.
rec-missing-plugin = Hai installato il plugin?

err-plugin-identity = '{$plugin_name}' ha fallito gestendo un'identità: {$message}
err-plugin-recipient = '{$plugin_name}' ha fallito gestendo il destinatario {$recipient}: {$message}
err-plugin-multiple = Il plugin ha riportato errori multipli:

err-read-identity-encrypted-without-passphrase =
    Il file di identità '{$filename}' è cifrato con {-age} ma non con una passphrase.
err-read-identity-not-found = File di identità non trovato: {$filename}

err-read-invalid-recipient = Destinatario '{$recipient}' invalido.

## Encrypted identities

encrypted-passphrase-prompt = Inserisci la passphrase per l'identità cifrata '{$filename}'

encrypted-warn-no-match = Attenzione: il file di identità cifrato '{$filename}' non corrisponde a nessuno dei destinatari

## Plugin identities

plugin-waiting-on-binary = In attesa di {$binary_name}...

## SSH identities

ssh-passphrase-prompt = Inserisci la passphrase per la chiave OpenSSH '{$filename}'

ssh-unsupported-key = Chiave SSH non supportata: {$name}

ssh-insecure-key-format =
    Formato della Chiave Crittografica Non Sicuro
    ---------------------------------------------
    Precedentemente alla versione 7.8 di OpenSSH, se una password veniva
    impostata quando si generava una nuova chiave DSA, ECDSA, o RSA, ssh-keygen
    avrebbe crittografato la chiave usando un formato PEM cifrato.

    Puoi migrare la tua chiave nel formato della chiave privata SSH
    crittografata (supportato dalla versione 6.5 di OpenSSH in poi, rilasciata
    nel gennaio 2014) cambiando la passphrase associata con il seguente comando:

    {"    "}{$change_passphrase}

    Se stai usando una versione di OpenSSH tra 6.5 e 7.7 (come quella
    predefinita di Ubuntu 18.04 LTS), puoi usare il comando seguente per forzare
    la generazione delle chiavi nel nuovo formato:

    {"    "}{$gen_new}

ssh-unsupported-cipher =
    Cifrario Non Supportato per la Chiave SSH Crittografata
    -------------------------------------------------------
    OpenSSH supporta internamente diversi cifrari per chiavi crittografate, ma
    ne ha generate direttamente solo alcune di queste. {-rage} supporta tutti i
    cifrari che ssh-keygen potrebbe generare, e viene aggiornato caso per caso
    con il supporto a cifrari non standard. La tua chiave usa un cifrario
    attualmente non supportato ({$cipher}).

    Se vorresti il supporto per questo tipo di chiave, per favore apri una
    segnalazione qui:

    {$new_issue}

ssh-unsupported-key-type =
    Tipo di Chiave SSH Non Supportato
    ---------------------------------
    OpenSSH supporta diversi tipi di chiavi, ma {-rage} ne supporta solo alcuni;
    specificatamente, i tipi '{-ssh-rsa}' e '{-ssh-ed25519}'. Questa chiave SSH
    è del tipo '{$key_type}', che non è supportato.
