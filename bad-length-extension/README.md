# Length extension attacks

## What it is

A length extension attack is a way to bypass the use of a hash algorithm to
verify a message.

For example, Alice wants to send a message to Bob, and prove it came from her.
The content of the message isn't sensitive, so there is no need to encrypt it,
but she does want to authenticate it. If Alice and Bob both know a shared
secret, we could perform this authentication step as follows:

	Alice:	send MESSAGE + HASH("secret" + MESSAGE)
	Bob:	receive MESSAGE
		compute HASH("secret" + MESSAGE)
		compare computed hash to received hash

Since no other party knows "secret", it would not be possible for anybody else
to compute the hash for an arbitrary message.

However, a lot of hash algorithms in current use have the following property:

	H1 = HASH(MSG1)
	H2 = CONTINUE_HASH(H1, MSG2)
	H2 == HASH(MSG1+MSG2)

This shows us that it is possible to add extra data on to the end of Alice's
MESSAGE, and update the HASH successfully, even without knowing the secret. This
is a length extension attack.

## How to avoid it

If you are counting on using some secret shared between two parties to verify
the code, then use an HMAC. The HMAC construct is specifically designed for
exactly this situation, and has stood up to cryptanalysis.

If there is no need for a shared secret, then in general I recommend that you
always use one of the truncated SHA-2 forms:
- SHA256/224 (preferred on 32-bit systems) — digests are 28 bytes
- SHA512/224 (preferred on 64-bit systems) — digests are 28 bytes
- SHA512/256 (preferred on 64-bit systems) — digests are 32 bytes
- SHA512/384 (preferred on 64-bit systems) — digests are 48 bytes

Try modifying the example to use one of these hash algorithms, and you will see
that the attack fails. This is because the length extension attack only works if
the attacker can see the full state of the hash.

In general using the truncated forms in code even when you're not expecting it
to be vulnerable to length extension attacks will provide a small extra
guarantee that nobody can tamper with your data.
