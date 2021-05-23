
Automatically find crypto constants in the loaded program - allows to very quickly identify crypto code.

![Example result: Crypto constants found in libcrypto.a](./img/yara.png)

Runs yara with the patterns found in yara-crypto.yar on the current program. The Yara rules are licensed under GPLv2. In addition @phoul's SHA256 rule was added.

Requires `yara` to be in `$PATH`.