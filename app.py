import secrets
from hashlib import sha3_256

from eth_keys import keys

# Sanity check for https://vanity-eth.tk/
private_key_hex = str(hex(secrets.randbits(256))[2:])
# private_key_hex = "256-bit-number-in-hex"
private_key_bytes = bytes.fromhex(private_key_hex)
public_key_hex = keys.PrivateKey(private_key_bytes).public_key
public_key_bytes = bytes.fromhex(str(public_key_hex)[2:])
keccak256_of_public_key_bytes = sha3_256(public_key_bytes).hexdigest()
public_address = keys.PublicKey(public_key_bytes).to_address()
checksum = keys.PublicKey(public_key_bytes).to_checksum_address()

print(f"""
{private_key_hex=}
{public_key_hex=}
{keccak256_of_public_key_bytes=}
{public_address=}
{checksum=}
""")