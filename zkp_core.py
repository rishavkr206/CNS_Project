# zkp_core.py
import secrets

# -----------------------------------------------------------------------------
# 1. Public parameters (demo prime + generator)
# -----------------------------------------------------------------------------
# For a real system, use a large safe prime (2048+ bits) and proper generator.
# Here we use a 127-bit Mersenne prime for simplicity:
p = 2**127 - 1
g = 3

# -----------------------------------------------------------------------------
# 2. Key‐pair generation (registration)
# -----------------------------------------------------------------------------
def generate_keypair():
    """
    Returns (x, y):
      x = private key ∈ [1, p−2]
      y = public key = g^x mod p
    """
    x = secrets.randbelow(p - 1) + 1
    y = pow(g, x, p)
    return x, y

# -----------------------------------------------------------------------------
# 3. Commitment (prover step 1)
# -----------------------------------------------------------------------------
def generate_commitment():
    """
    Returns (r, t):
      r = random nonce ∈ [1, p−2]
      t = g^r mod p
    """
    r = secrets.randbelow(p - 1) + 1
    t = pow(g, r, p)
    return r, t

# -----------------------------------------------------------------------------
# 4. Challenge (verifier step 2)
# -----------------------------------------------------------------------------
def generate_challenge(bit_length=16):
    """
    Returns a random integer challenge c ∈ [0, 2^bit_length)
    """
    return secrets.randbelow(1 << bit_length)

# -----------------------------------------------------------------------------
# 5. Response (prover step 3)
# -----------------------------------------------------------------------------
def compute_response(r, x, c):
    """
    Returns s = (r + c·x) mod (p−1)
    """
    return (r + c * x) % (p - 1)

# -----------------------------------------------------------------------------
# 6. Verification (verifier step 4)
# -----------------------------------------------------------------------------
def verify_schnorr(t, s, c, y):
    """
    Checks whether g^s mod p == t * y^c mod p.
    Returns True if valid proof, else False.
    """
    lhs = pow(g, s, p)
    rhs = (t * pow(y, c, p)) % p
    return lhs == rhs

def schnorr_protocol_simulation():
    """
    Simulates a full Schnorr protocol run:
    1. Registration (key generation)
    2. Commitment (prover)
    3. Challenge (verifier)
    4. Response (prover)
    5. Verification (verifier)
    Prints each step and result.
    """
    print("=== Schnorr Protocol Simulation ===")
    # 1. Registration (user generates key pair)
    x, y = generate_keypair()
    print(f"Private key (x): {x}")
    print(f"Public key (y): {y}")

    # 2. Commitment (prover)
    r, t = generate_commitment()
    print(f"Prover picks random r: {r}")
    print(f"Prover sends commitment t: {t}")

    # 3. Challenge (verifier)
    c = generate_challenge()
    print(f"Verifier sends challenge c: {c}")

    # 4. Response (prover)
    s = compute_response(r, x, c)
    print(f"Prover computes response s: {s}")

    # 5. Verification (verifier)
    valid = verify_schnorr(t, s, c, y)
    print(f"Verifier checks proof: {'VALID' if valid else 'INVALID'}")

# Uncomment the next line to run the simulation directly
schnorr_protocol_simulation()