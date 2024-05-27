# CryptoFetterX
This is a program for strong file encryption (under development).

## Key features

<ul>
	<li>Unable to identify the file as encrypted by CryptoFetterX</li>
    <li>In the encrypted file, there is no information that helps the attacker (encryption algorithms, KDF, etc.)</li>
    <li>There are no default values for algorithms because default values are vulnerable targets</li>
    <li>Cipher algorithms: AES, Serpent, Camellia, Twofish</li>
    <li>KDF algorithms: Argon2id, Scrypt</li>
    <li>The integrity of the encrypted file is monitored by using GCM encryption mode</li>
    <li>It is possible to use key files: KECCAK-1600 (512) hash is used as salt for KDF</li>
    <li>Botan crypto library is used for encryption</li>
    <li>This application does not require administrator rights</li>
</ul>
<strong>Dependencies</strong>:
<ul>
    <li>Botan 3.4</li>
    <li>bzip2 1.0.8</li>
    <li>wxWidgets 3.2.5</li>
</ul>
<strong>Planned</strong>:
<ul>
    <li>Bugfix: Perform large-scale code refactoring from alpha version to release</li>
    <li>Release CryptoFetterX for Linux and macOS</li>
    <li>Add detachable headers to files to speed up the decryption process on weak computers</li>
</ul>

# Donations

<strong>Please donate to CryptoFetterX. This is a project that I spend a lot of time on and do not make any money from. CryptoFetterX needs support from the community</strong>

<strong>Monero Wallet (XMR)</strong>: 8AcFyDHXmqQ7Swb2imehDb6eWK3ruSeeSABYYZBkugc3h5cckyhBnbZPZmZPRhcPBvZN7K4LFo9QfTtSqx2kyUwnG79eF9B
<strong>Dash Wallet</strong>: XoVm3LDinKk2SibGoHVPV1dFQa79LGEiEx

## Thank you for your support and understanding
