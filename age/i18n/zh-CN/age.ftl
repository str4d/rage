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

cli-secret-input-required = 必输入内容
cli-secret-input-mismatch = 所输内容不匹配

cli-passphrase-desc = 输入密码短语 (留空则自动生成强密码短语)
cli-passphrase-prompt = 密码短语
cli-passphrase-confirm = 确认密码短语

-flag-armor = -a/--armor
-flag-output = -o/--output
-output-stdout = -o -

cli-truncated-tty = 被截断；请采用管道 （pipe）、重定向 （redirect）、或 {-flag-output} 以解密整个文件

err-detected-binary = 检测到未能打印的数据；拒绝输出至终端。
rec-detected-binary = 采用 '{-output-stdout}' 强制打印。

err-deny-binary-output = 拒绝输出二进制内容至终端。
rec-deny-binary-output = 您是不是要采用 {-flag-armor}？ {rec-detected-binary}

## Errors

err-decryption-failed = 解密失败

err-excessive-work = 密码短语的工作参数 （work parameter） 过高。
rec-excessive-work = 解密大约需要 {$duration} 秒

err-header-invalid = 标头无效

err-header-mac-invalid = 标头消息认证码 （MAC） 无效

err-key-decryption = 未能解密加密密钥

err-no-matching-keys = 未搜索到匹配的密钥

err-unknown-format = 未知的 {-age} 格式。
rec-unknown-format = 您尝试更新至最新版本了吗？

## SSH identities

ssh-passphrase-prompt = 输入 OpenSSH 密钥 '{$filename}' 的密码短语

ssh-unsupported-identity = 该 SSH 身份不受支持： {$name}

ssh-insecure-key-format =
    不安全的私钥格式
    --------------
    在 OpenSSH 7.8 版本之前，若在生成新 DSA、ECDSA、或 RSA 密钥时设定口令, ssh-keygen 会使用 PEM 加密格式
    来加密密钥。 该加密格式是不安全的，且不应继续使用。

    若您想将密钥迁移至加密 SSH 私钥格式 (该格式从 2014 一月份的 OpenSSH 6.5 版本已受支持)， 可采用此命令以更换
    它的密码短语:

    {"    "}{$change_passphrase}

    若您目前使用的是 OpenSSH 6.5 —— 7.7 版本 (例如 Ubuntu 18.04 LTS 默认提供的 OpenSSH）, 可采用此命令以
    强制使用新格式生成密钥：

    {"    "}{$gen_new}

ssh-unsupported-cipher =
    未受支持的 SSH 加密密钥密码
    ------------------------
    OpenSSH 内部支持几种不同的加密钥密码 （ciphers）,但其中只有少数是直接生成的。{-rage} 支持所有
    ssh-keygen 可生成的密码， 并且正在进行更新，以在个案基础上扩展非标准密码支持。您的密钥使用的密码 ({$cipher})
    当前不受支持。

    若您希望该密钥类型可受支持, 请在此创建新议题 （issue）：

    {$new_issue}
