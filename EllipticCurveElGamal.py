import random


class EllipticCurveElGamal:
    def __init__(self, prime_modulus, coeff_a, coeff_b, base_point, curve_order):
        self.prime_modulus = prime_modulus  # The prime modulus of the finite field
        self.coeff_a = coeff_a  # Curve coefficient a
        self.coeff_b = coeff_b  # Curve coefficient b
        self.base_point = base_point  # Base point G = (x, y)
        self.curve_order = curve_order  # Order of the base point

    ########################################
    ### Modular arithmetic and point ops ###
    ########################################

    def compute_modular_inverse(self, value, modulus):
        if value == 0:
            raise ZeroDivisionError("Cannot compute modular inverse for 0.")
        elif value < 0:
            return modulus - self.compute_modular_inverse(-value, modulus)
        else:
            return self.extended_euclidean_algorithm(value, modulus)

    def extended_euclidean_algorithm(self, value, modulus):
        if modulus == 0:
            raise ValueError("Modulus must be greater than 0.")

        curr_s, prev_s = 0, 1
        curr_t, prev_t = 1, 0
        curr_r, prev_r = modulus, value
        while curr_r != 0:
            quotient = prev_r // curr_r
            prev_t, curr_t = curr_t, prev_t - quotient * curr_t
            prev_s, curr_s = curr_s, prev_s - quotient * curr_s
            prev_r, curr_r = curr_r, prev_r - quotient * curr_r

        if prev_r != 1:
            raise ValueError(f"No modular inverse exists for {value} modulo {modulus}.")

        return prev_s % modulus

    def calculate_slope(self, point1, point2):
        return ((point2[1] - point1[1]) * self.compute_modular_inverse(point2[0] - point1[0],
                                                                       self.prime_modulus)) % self.prime_modulus

    def add_points_to_curve(self, point1, point2):
        if point1 is None:
            return point2
        if point2 is None:
            return point1
        if point1 == point2:
            return self.double_points_on_curve(point1)
        if point1[0] == point2[0] and (point1[1] != point2[1] or point1[1] == 0):
            return None  # Point at infinity

        slope = self.calculate_slope(point1, point2)
        x3 = (slope ** 2 - point1[0] - point2[0]) % self.prime_modulus
        y3 = (slope * (point1[0] - x3) - point1[1]) % self.prime_modulus
        return (x3, y3)

    def double_points_on_curve(self, point):
        if point is None:
            return None

        slope = ((3 * point[0] ** 2 + self.coeff_a) * self.compute_modular_inverse(2 * point[1],
                                                                                   self.prime_modulus)) % self.prime_modulus
        x = (slope ** 2 - 2 * point[0]) % self.prime_modulus
        y = (slope * (point[0] - x) - point[1]) % self.prime_modulus
        return (x, y)

    def multiply_point_on_curve(self, scalar, point):
        result = None
        current = point

        while scalar > 0:
            if scalar & 1:
                result = self.add_points_to_curve(result, current)
            current = self.double_points_on_curve(current)
            scalar >>= 1

        return result

    ######################################
    ### EC ElGamal keygen, encrypt, decrypt ###
    ######################################

    def generate_private_key(self):
        """Generate a random private key in the range [1, curve_order-1]."""
        return random.randint(1, self.curve_order - 1)

    def generate_public_key(self, private_key):
        """Compute public key Q = d * G."""
        return self.multiply_point_on_curve(private_key, self.base_point)

    def encrypt(self, message_point, public_key):
        """
        Encrypt a message point using the receiver's public key.
        Returns ciphertext tuple (C1, C2).
        """
        k = random.randint(1, self.curve_order - 1)
        C1 = self.multiply_point_on_curve(k, self.base_point)
        kQ = self.multiply_point_on_curve(k, public_key)
        C2 = self.add_points_to_curve(message_point, kQ)
        return (C1, C2)

    def decrypt(self, ciphertext, private_key):
        """
        Decrypt ciphertext (C1, C2) using private key.
        Returns original message point.
        """
        C1, C2 = ciphertext
        dC1 = self.multiply_point_on_curve(private_key, C1)
        # Invert dC1's y-coordinate to subtract
        inv_dC1 = (dC1[0], (-dC1[1]) % self.prime_modulus)
        message_point = self.add_points_to_curve(C2, inv_dC1)
        return message_point


# SECP256k1 parameters
prime_modulus = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
coeff_a = 0
coeff_b = 7
base_x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
base_y = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
base_point = (base_x, base_y)
curve_order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Create the ElGamal object
elgamal = EllipticCurveElGamal(prime_modulus, coeff_a, coeff_b, base_point, curve_order)

# Key generation
priv_key = elgamal.generate_private_key()
pub_key = elgamal.generate_public_key(priv_key)

# Example message point (must be on curve)
message_point = base_point  # Example only

# Encrypt
ciphertext = elgamal.encrypt(message_point, pub_key)

# Decrypt
decrypted_point = elgamal.decrypt(ciphertext, priv_key)

assert decrypted_point == message_point
print("Encryption and decryption successful!")
