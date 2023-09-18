# pseudonymization_java

Java version of a pseudonymization library using Bouncy Castle cryptography.
The key derivation algorithms Scrypt and PDKDF2 (PKCS#5) are used as salted hashing algorithms for generating the pseudonyms.
GSON is used for supporting serialization and deserialization of the pseudonymization salts storage.
