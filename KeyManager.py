import random
from EllipticCurveElGamal import elgamal

class KeyManager:
    def __init__(self):
        # Hardcoded private keys.
        self.private_keys = [
            1357924680,
            2468135790,
            1122334455,
            9988776655,
            1231231231,
            9879879879,
            1111222233,
            4444555566,
            7777888899,
            5555666677
        ]
        
        # Hardcoded Schnorr keys.
        self.schnorr_parameters = [
            [211, 7, 2],
            [163, 3, 2],
            [181, 5, 2],
            [223, 37, 2],
            [157, 13, 2],
            [173, 43, 2],
            [137, 17, 2],
            [251, 5, 2],
            [211, 7, 2],
            [251, 5, 2],
            [223, 37, 2],
            [173, 43, 2],
            [137, 17, 2],
            [251, 5, 2],
            [223, 37, 2],
            [163, 3, 2],
            [139, 23, 2],
            [251, 5, 2],
            [137, 17, 2],
            [227, 113, 2]
        ]
        
        # Dynamically calculate public keys based on the private keys
        self.public_keys = [elgamal.generate_public_key(d) for d in self.private_keys]

        # Combine private and public keys into pairs
        self.key_pairs = list(zip(self.private_keys, self.public_keys))
    
    # Function: getPrivateAndPublicKey
    # Returns a random private and public key pair.
    def getPrivateAndPublicKey(self):
        if not self.key_pairs:
            raise ValueError("No more key pairs available.")
        
        # Randomly choose a key pair and remove it from the list
        chosen_pair = random.choice(self.key_pairs)
        self.key_pairs.remove(chosen_pair)
        return chosen_pair
    
    # Function: getRandomSchnorrParameters():
    # Returns a random Schnorr parameters
    def getRandomSchnorrParameters(self):    
        return random.choice(self.schnorr_parameters)