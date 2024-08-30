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

cli-secret-input-required = Требуется ввод
cli-secret-input-mismatch = Входы не совпадают

cli-passphrase-desc = Введите ключевую фразу (оставьте пустой, чтобы автогенерировать безопасную фразу)
cli-passphrase-prompt = Парольная фраза
cli-passphrase-confirm = Подтвердить парольную фразу

-flag-armor = -a/--armor
-flag-output = -o/--output
-output-stdout = -o -

cli-truncated-tty = усеченный; используйте трубу, перенаправление или {-flag-output} для расшифровки всего файла

err-detected-binary = обнаружены непечатаемые данные; отказ от вывода в терминал.
rec-detected-binary = Принудительно используйте '{-output-stdout}'.

err-deny-binary-output = отказ от вывода бинарных данных в терминал.
rec-deny-binary-output = Возможно, вы хотели использовать {-flag-armor}? {rec-detected-binary}

err-deny-overwrite-file = отказ от перезаписи существующего файла '{$filename}'.

## Identity file errors

err-failed-to-write-output = Не удалось записать в выходной файл: {$err}

err-identity-file-contains-plugin = Файл идентификации '{$filename}' содержит идентификаторы для '{-age-plugin-}{$plugin_name}'.
rec-identity-file-contains-plugin = Попробуйте использовать '{-age-plugin-}{$plugin_name}' для преобразования этого идентификатора в получателя.

err-no-identities-in-file = Идентификаторы в файле '{$filename}' не найдены.
err-no-identities-in-stdin = Идентификаторы в стандартном вводе не найдены.

## Errors

err-decryption-failed = Ошибка дешифрования

err-excessive-work = Чрезмерный параметр работы для парольной фразы.
rec-excessive-work = Дешифрование займет примерно {$duration} секунд.

err-header-invalid = Недействительный заголовок

err-header-mac-invalid = Недействительный MAC заголовка

err-key-decryption = Не удалось расшифровать зашифрованный ключ

err-missing-recipients = Отсутствуют получатели.

err-no-matching-keys = Не найдены подходящие ключи

err-unknown-format = Неизвестный формат {-age}.
rec-unknown-format = Попробуйте обновиться до последней версии.

err-missing-plugin = Не удалось найти '{$plugin_name}' в PATH.
rec-missing-plugin = Установили ли вы плагин?

err-plugin-identity = '{$plugin_name}' не смог использовать идентификатор: {$message}
err-plugin-recipient = '{$plugin_name}' не смог использовать получателя {$recipient}: {$message}

err-plugin-died = '{$plugin_name}' неожиданно завершил работу.
rec-plugin-died-1 = Если вы разрабатываете плагин, запустите с переменной окружения {$env_var} для получения дополнительной информации.
rec-plugin-died-2 = Внимание: это печатает частную информацию ключа шифрования в стандартный вывод ошибок.

err-plugin-multiple = Плагин вернул несколько ошибок:

err-read-identity-encrypted-without-passphrase =
    Файл идентификации '{$filename}' зашифрован с использованием {-age}, но без парольной фразы.
err-read-identity-not-found = Файл идентификации не найден: {$filename}

err-read-invalid-recipient = Недействительный получатель '{$recipient}'.

err-read-invalid-recipients-file =
    Файл получателей '{$filename}' содержит данные, не относящиеся к получателям, в строке {$line_number}.

err-read-missing-recipients-file = Файл получателей не найден: {$filename}

err-read-multiple-stdin = Стандартный ввод не может использоваться для нескольких целей.

err-read-rsa-modulus-too-large =
    Слишком большой модуль RSA
    ---------------------
    {-openssh} поддерживает различные размеры модуля RSA, но {-rage} поддерживает
    только публичные ключи максимум {$max_size} бит, чтобы предотвратить условия
    отказа в обслуживании (DoS) при шифровании для ненадежных публичных ключей.

err-read-rsa-modulus-too-small = Размер ключа RSA слишком мал.

err-stream-last-chunk-empty = Последний чанк STREAM пуст. Пожалуйста, сообщите об этом и/или попробуйте старую {-rage} версию.

## Encrypted identities

encrypted-passphrase-prompt = Введите парольную фразу для зашифрованной идентификации '{$filename}'

encrypted-warn-no-match = Предупреждение: зашифрованный файл идентификации '{$filename}' не соответствует получателям файла

## Plugin identities

plugin-waiting-on-binary = Ожидание {$binary_name}...

## SSH identities

ssh-passphrase-prompt = Введите парольную фразу для {-openssh} ключа '{$filename}'

ssh-unsupported-key = Неподдерживаемый SSH ключ: {$name}

ssh-insecure-key-format =
    Небезопасный формат зашифрованного ключа
    -----------------------------
    До версии {-openssh} 7.8, если при создании нового ключа DSA, ECDSA или RSA
    был установлен пароль, {-ssh-keygen} шифровал ключ, используя зашифрованный
    формат PEM. Этот формат шифрования устарел и не должен использоваться.

    Вы можете мигрировать свой ключ в зашифрованный формат частного ключа SSH
    (который поддерживается с версии 6.5, выпущенной в январе 2014 года),
    изменив его парольную фразу с помощью следующей команды:

    {"    "}{$change_passphrase}

    Если вы используете версию {-openssh} между 6.5 и 7.7 (например, стандартную
    версию {-openssh} в Ubuntu 18.04 LTS), вы можете использовать следующую
    команду для создания ключей с использованием нового формата:

    {"    "}{$gen_new}

ssh-unsupported-cipher =
    Неподдерживаемый шифр для зашифрованного SSH ключа
    ----------------------------------------
    {-openssh} внутренне поддерживает несколько различных шифров для зашифрованных
    ключей, но только некоторые из них генерируются напрямую. {-rage} поддерживает
    все шифры, которые может генерировать {-ssh-keygen}, и обновляется по мере
    необходимости для поддержки нестандартных шифров. Ваш ключ использует в
    настоящее время неподдерживаемый шифр ({$cipher}).

    Если вы хотите поддержки этого типа ключа, пожалуйста, откройте проблему здесь:

    {$new_issue}

ssh-unsupported-key-type =
    Неподдерживаемый тип SSH ключа
    ------------------------
    {-openssh} поддерживает различные типы ключей, но {-rage} поддерживает только
    подмножество этих для обратной совместимости, в частности типы ключей
    '{-ssh-rsa}' и '{-ssh-ed25519}'. Этот SSH ключ использует неподдерживаемый
    тип ключа '{$key_type}'.

ssh-unsupported-security-key =
    Неподдерживаемый аппаратный аутентификатор SSH
    --------------------------------------
    Версия {-openssh} 8.2p1 добавила поддержку аппаратных аутентификаторов
    {-fido-u2f}, включая аппаратные ключи безопасности, такие как {-yubikeys}.
    {-rage} не работает с этими типами ключей SSH, потому что их протокол не
    поддерживает шифрование. Этот SSH ключ использует несовместимый тип
    '{$key_type}'.

    Если у вас есть совместимый аппаратный ключ безопасности, вы должны
    использовать этот плагин:

    {$age_plugin_yubikey_url}

    Аппаратный ключ безопасности, используемый одновременно с {-openssh} и
    этим плагином будет иметь отдельный публичный SSH-ключ и получателя
    шифрования {-age}, потому что плагин реализует протокол {-piv}.
