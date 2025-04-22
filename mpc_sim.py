import shamirs
from ecdsa import SECP256k1

# 1) Define your secret (e.g. a private‐key placeholder)
SECRET = 0xCAFEBABE1234

# 2) Parties in Copper’s 2-of-3 model
PARTIES = ["Client", "Copper", "TTP"]

# 3) Use the curve order as modulus (256-bit prime)
MODULUS = SECP256k1.order

# 4) Generate 3 shares (threshold=2) over GF(MODULUS)
raw_shares = shamirs.shares(SECRET, quantity=3, threshold=2, modulus=MODULUS)

# 5) Map shares to parties
shares = dict(zip(PARTIES, raw_shares))

def reconstruct(party_a: str, party_b: str):
    """
    Reconstruct secret using shares from any two parties.
    """
    subset = [shares[party_a], shares[party_b]]
    # Adjust the call to interpolate based on the correct parameters
    return shamirs.interpolate(subset, threshold=2)  # Removed modulus

# Example verification when run directly
if __name__ == "__main__":
    recovered = reconstruct("Client", "Copper")
    print("Original Secret:    ", hex(SECRET))
    print("Shares:")
    for p, s in shares.items():
        print(f"  {p}: {s}")
    print("Reconstructed (Client+Copper):", hex(recovered))
