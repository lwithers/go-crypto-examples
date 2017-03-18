# Crypto examples for Go

While writing a replacement for the awful Java keystore tool, I worried that
people might re-use the code in that as though it was a good example. It is not.
This repository acts as a place to hold simple, concise demonstrations of how
cryptography should be done.

There are individual README files in each example's subdirectory that contain
further details.

## Good example list

- **hmac**: hash-based message authentication code. Use this if you want to
	prove the authenticity of a message (or other piece of data).

- **password-encrypt**: how to encrypt some data with a password.

## Bad example list

- **bad-length-extension**: shows a length extension attack in practice. Use
	**hmac** to avoid these.
