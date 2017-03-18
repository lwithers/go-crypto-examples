# HMAC

*Hash-based message authentication codes* are a cryptographically-secure
mechanism for proving the authenticity of a message. Note that they do not
encrypt the message.

If you are ever considering making a construct such as `HASH(key + message)`,
then stop immediately and use an HMAC instead.

This example shows how easy it is to use an HMAC to verify the authenticity of
a message. Note one subtlety: to avoid timing attacks, you must use a constant
time comparison function (`hmac.Equal`).
