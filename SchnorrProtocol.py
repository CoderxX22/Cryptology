import hashlib
import random
from sympy import isprime, randprime, factorint

# Implementation of the Schnorr Signature scheme.
class SchnorrProtocol:
    
    # Constructor.
    def __init__(self, prime, subgroup_order, generator):
        self.prime = prime                      # The modulus for the finite field
        self.subgroup_order = subgroup_order    # The order of the subgroup.
        self.generator = generator              # The generator of the subgroup.
        self.private_key = None                 # The private key of the user.
        self.public_key = None                  # The public key of the user.

    # Function: create_key_pair
    # Generate the private and public keys.
    def create_key_pair(self):
        self.private_key = random.randint(1, self.subgroup_order - 1) # Random scalar for private key.
        self.public_key = pow(self.generator, self.private_key) % self.prime # Public key calculation.

    # Function: compute_hash
    # Calculate the hash of a given input.
    def compute_hash(self, message):
        return int(hashlib.sha256(message.encode()).hexdigest(), 16)

    # Function: generate_signature
    # Create a Schnorr signature for a given message.
    def generate_signature(self, message):
        if self.private_key is None:
            raise ValueError("Private key is not set. Generate keys first.")

        # Select a random nonce
        nonce = random.randint(1, self.subgroup_order - 1)

        # Compute the commitment
        commitment = pow(self.generator, nonce)

        # Compute the challenge
        challenge = self.compute_hash(f"{commitment}{message}")

        # Compute the response
        response = (nonce + self.private_key * challenge)

        return commitment, response

    # Function: validate_signature
    # Verify the Schnorr signature.
    def validate_signature(self, message, commitment, response, public_key):
        # Compute the challenge
        challenge = self.compute_hash(f"{commitment}{message}")

        # Recompute values for verification
        return (pow(self.generator, response, self.prime)) == ((pow(public_key, challenge, self.prime) * commitment) % self.prime)


# Function: create_schnorr_parameters
# Generate parameters for the Schnorr Signature scheme.
def create_schnorr_parameters(bit_size):
    while True:
        # Generate a random prime modulus
        prime = randprime(2 ** (bit_size - 1), 2 ** bit_size)

        # Factorize (p - 1) to find a suitable subgroup order
        factors = factorint(prime - 1)
        potential_orders = [factor for factor, exponent in factors.items() if isprime(factor)]

        if not potential_orders:
            continue

        subgroup_order = max(potential_orders)

        if subgroup_order > 1 and subgroup_order < prime - 1:
            break

    return prime, subgroup_order, 2