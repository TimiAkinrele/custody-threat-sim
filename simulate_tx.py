import shamirs
from ecdsa import SigningKey, SECP256k1, VerifyingKey
import hashlib, json

class MPCWallet:
    def __init__(self, threshold=2, parties=None):
        self.threshold = threshold
        self.parties = parties or ["Client", "Copper", "TTP"]

        # 1) Generate ECDSA keypair
        self._sk = SigningKey.generate(curve=SECP256k1)
        self._vk = self._sk.get_verifying_key()

        # 2) Convert private key bytes to integer
        sk_int = int.from_bytes(self._sk.to_string(), 'big')

        # 3) Use the curve order as prime modulus
        self.modulus = SECP256k1.order

        # 4) Create Shamir shares
        raw_shares = shamirs.shares(
            sk_int,
            quantity=len(self.parties),
            threshold=self.threshold,
            modulus=self.modulus
        )
        self.shares = dict(zip(self.parties, raw_shares))

    @property
    def public_key_hex(self):
        return self._vk.to_string("compressed").hex()

    def reconstruct_sk(self, party_a, party_b):
        """
        Reconstruct SigningKey from two shares.
        """
        subset = [self.shares[party_a], self.shares[party_b]]
        sk_int = shamirs.interpolate(
            subset,
            threshold=self.threshold  # Removed modulus
        )
        sk_bytes = sk_int.to_bytes(32, 'big')
        return SigningKey.from_string(sk_bytes, curve=SECP256k1)

    def sign_transaction(self, sk, tx_payload):
        """
        Sign JSON payload with ECDSA.
        """
        message = json.dumps(tx_payload, sort_keys=True).encode()
        digest = hashlib.sha256(message).digest()
        return sk.sign_digest(digest).hex()

    def verify_signature(self, signature_hex, tx_payload):
        """
        Verify signature with the public key.
        """
        sig = bytes.fromhex(signature_hex)
        message = json.dumps(tx_payload, sort_keys=True).encode()
        digest = hashlib.sha256(message).digest()
        return self._vk.verify_digest(sig, digest)
