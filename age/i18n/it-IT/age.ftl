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

## Errors

err-decryption-failed = Decrittazione fallita

err-excessive-work = Parametro di lavoro per la passphrase troppo elevato.
rec-excessive-work = La decrittazione impiegherà circa {$duration} secondi.

err-header-invalid = L'header è invalido

err-header-mac-invalid = L'header MAC è invalido

err-key-decryption = La decrittazione di una chiave crittografata è fallita

err-no-matching-keys = Nessuna chiave corrispondente trovata

err-unknown-format = Formato {-age} sconosciuto.
rec-unknown-format = Hai provato ad aggiornare all'ultima versione?

## SSH identities

ssh-passphrase-prompt = Inserisci la passphrase per la chiave OpenSSH '{$filename}'

ssh-unsupported-identity = Identità SSH non supportata: {$name}

ssh-insecure-key-format =
    Formato della Chiave Crittografica Insicuro
    -------------------------------------------
    Precedentemente alla versione 7.8 di OpenSSH, se una password veniva
    impostata quando si generava una nuova chiave DSA, ECDSA, o RSA, ssh-keygen
    avrebbe crittografato la chiave usando un formato PEM crittato.

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

    Se vorresti il sopporto per questo tipo di chiave, per favore apri una
    issue qui:

    {$new_issue}