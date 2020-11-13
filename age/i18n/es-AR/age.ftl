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

## CLI helpers

cli-secret-input-required = requiere una entrada de texto
cli-secret-input-mismatch = las entrada provistas no coinciden

cli-passphrase-desc = Escriba su frase contraseña (dejar vacío para autogenerar una segura)
cli-passphrase-prompt = Frase contraseña
cli-passphrase-confirm = Confirmar frase contraseña

-flag-armor = -a/--armor
-flag-output = -o/--output
-output-stdout = -o -

cli-truncated-tty = truncado; use un pipe, una redirección, or {-flag-output} para desencriptar todo el archivo

err-detected-binary = datos no imprimibles detectados; no se escribira la salida a la terminal.
rec-detected-binary = Forzar con '{-output-stdout}'.

err-deny-binary-output = rechazando escribir output binario a la terminal.
rec-deny-binary-output = ¿Querias usar {-flag-armor}? {rec-detected-binary}

## Errors

err-decryption-failed = Desencripción fallida.

err-excessive-work = Parámetro excesivo de trabajo para frase contraseña.
rec-excessive-work = La desencripción tomara alrededor de {$duration} segundos.

err-header-invalid = Encabezado inválido

err-header-mac-invalid = MAC de encabezado inválido.

err-key-decryption = No se pudo desencriptar una clave encriptada.

err-no-matching-keys = No se encontraron claves coincidentes.

err-unknown-format = Formato {-age} desconocido.
rec-unknown-format = ¿Has intentado actualizar a la última versión?

## SSH identities

ssh-passphrase-prompt = Escribe frase contraseña para clave OpenSSH '{$filename}'

ssh-unsupported-identity = Identidad SSH no soportada: {$name}

ssh-insecure-key-format =
    Formato de Clave Encriptada inseguro
    ------------------------------------
    Antes de OpenSSH version 7.8, su una contraseña era establecida al generar
    una nueva clave DS, ECDSA o RSA, ssh-keygen encriptaría dicha clave utilizando
    el formato PEM. Este formato de encripción es inseguro y no debería utilizarse
    más.

    Puedes migrar tu clave al formato de Clave Privada SSH (que has sido soportado
    por OpenSSH desde la versión 6.5, lanzada en enero de 2014) cambiado su frase
    contraseña (passphrase) con el siguiente comando:

    {"    "}{$change_passphrase}

    Si estas utilizando OpenSSH entre las versiones 6.5 y 7.7 (tal como el OpenSSH
    provisto por defecto en Ubuntu 18.04 LTS), puedes usar el siguiente comando para
    forzar la generación de claves utilizando el nuevo formato:
    
    {"    "}{$gen_new}

ssh-unsupported-cipher =
    Cifrado no soportado para Clave Encriptada SHH
    ----------------------------------------------
    OpenSSH soporta internamente varios cifrados diferentes para claves encriptadas,
    pero solo ha soportado solo algunos de pocos de ellos. {-rage} soporta todos
    los cifrados que ssh-keygen pudiera generar, y esta siendo actualizado
    caso a caso para soportar aquellos cifrados no-estándar. Tu clave utiliza
    un cifrado no soportado actualmente: ({$cipher}).
    
    Si quisieras soporte para este tipo de clave, por favor abre un issue aquí:

    {$new_issue}