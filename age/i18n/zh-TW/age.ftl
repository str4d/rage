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

cli-secret-input-required = 必輸入內容
cli-secret-input-mismatch = 所輸內容不匹配

cli-passphrase-desc = 輸入密碼短語 (留空則自動生成強密碼短語)
cli-passphrase-prompt = 密碼短語
cli-passphrase-confirm = 確認密碼短語

-flag-armor = -a/--armor
-flag-output = -o/--output
-output-stdout = -o -

cli-truncated-tty = 被截斷；請採用管道 （pipe）、重定向 （redirect）、或 {-flag-output} 以解密整個文件

err-detected-binary = 檢測到未能列印的數據；拒絕輸出至終端。
rec-detected-binary = 採用 '{-output-stdout}' 強制列印。

err-deny-binary-output = 拒絕輸出二進位內容至終端。
rec-deny-binary-output = 您是不是要採用 {-flag-armor}？ {rec-detected-binary}

## Errors

err-decryption-failed = 解密失敗

err-excessive-work = 密碼短語的工作參數 （work parameter） 過高。
rec-excessive-work = 解密大約需要 {$duration} 秒

err-header-invalid = 標頭無效

err-header-mac-invalid = 標頭消息認證碼 （MAC） 無效

err-key-decryption = 未能解密加密密鑰

err-no-matching-keys = 未搜索到匹配的密鑰

err-unknown-format = 未知的 {-age} 格式。
rec-unknown-format = 您嘗試更新至最新版本了嗎？

## SSH identities

ssh-passphrase-prompt = 輸入 OpenSSH 密鑰 '{$filename}' 的密碼短語

ssh-unsupported-identity = 該 SSH 身份不受支持： {$name}

ssh-insecure-key-format =
    不安全的私鑰格式
    --------------
    在 OpenSSH 7.8 版本之前，若在生成新 DSA、ECDSA、或 RSA 密鑰時設定口令, ssh-keygen 會使用 PEM 加密格式
    來加密密鑰。 該加密格式是不安全的，且不應繼續使用。

    若您想將密鑰遷移至加密 SSH 私鑰格式 (該格式從 2014 一月份的 OpenSSH 6.5 版本已受支持)， 可採用此命令以更換
    它的密碼短語:

    {"    "}{$change_passphrase}

    若您目前使用的是 OpenSSH 6.5 —— 7.7 版本 (例如 Ubuntu 18.04 LTS 默認提供的 OpenSSH）, 可採用此命令以
    強制使用新格式生成密鑰：

    {"    "}{$gen_new}

ssh-unsupported-cipher =
    未受支持的 SSH 加密密鑰密碼
    ------------------------
    OpenSSH 內部支持幾種不同的加密鑰密碼 （ciphers）,但其中只有少數是直接生成的。{-rage} 支持所有
    ssh-keygen 可生成的密碼， 並且正在進行更新，以在個案基礎上擴展非標準密碼支持。您的密鑰使用的密碼 ({$cipher})
    當前不受支持。

    若您希望該密鑰類型可受支持, 請在此創建新議題 （issue）：

    {$new_issue}
