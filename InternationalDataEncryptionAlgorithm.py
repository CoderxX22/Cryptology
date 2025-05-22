######################################################################
### International Data Encryption Algorithm - Output Feedback Mode ###
######################################################################

# This class implements the International Data Encryption Algorithm, a block cipher for 64-bit blocks
# with a 128-bit key. It supports encryption, decryption, and OFB mode.

# Constants
KEY_SIZE_BITS = 128
SUBKEY_COUNT = 52
BLOCK_SIZE_BITS = 64
SEGMENT_SIZE_BITS = 16
MODULUS = 65537
MAX_VALUE = 0xFFFF
IDEA_ROUNDS = 8
SHIFT_9_BITS = 9
SHIFT_7_BITS = 7

class InternationalDataEncryptionAlgorithm:
    def __init__(self, key):
        self.encryption_keys = self.generate_encryption_subkeys(key)
        self.decryption_keys = self.generate_decryption_subkeys(self.encryption_keys)

    ################################
    ### Key Generation Functions ###
    ################################

    # Function: generate_encryption_subkeys
    # Expands the 128-bit key into 52 subkeys (16 bits each) for encryption.
    def generate_encryption_subkeys(self, key):
        subkeys = []
        # Extract 8 subkeys directly from the key.
        for i in range(8):
            subkey = (key >> (KEY_SIZE_BITS - SEGMENT_SIZE_BITS - i * SEGMENT_SIZE_BITS)) & MAX_VALUE
            subkeys.append(subkey)
        
        # Generate the remaining 44 subkeys via cyclic rotation.
        for i in range(8, SUBKEY_COUNT):
            if (i % 8) < 6:
                subkey = ((subkeys[i - 8] << SHIFT_9_BITS) | (subkeys[i - 7] >> SHIFT_7_BITS)) & MAX_VALUE
            elif (i % 8) == 6:
                subkey = ((subkeys[i - 7] << SHIFT_9_BITS) | (subkeys[i - 14] >> SHIFT_7_BITS)) & MAX_VALUE
            elif (i % 8) == 7:
                subkey = ((subkeys[i - 15] << SHIFT_9_BITS) | (subkeys[i - 14] >> SHIFT_7_BITS)) & MAX_VALUE
            subkeys.append(subkey)
            
        return subkeys
    
    # Function: generate_decryption_subkeys
    # Generates decryption subkeys by reversing and transforming the encryption subkeys.
    def generate_decryption_subkeys(self, subkeys):
        dec_keys = [0] * SUBKEY_COUNT
        # Final round keys.
        dec_keys[48] = self.modular_inverse(subkeys[0])
        dec_keys[49] = -subkeys[1] & MAX_VALUE
        dec_keys[50] = -subkeys[2] & MAX_VALUE
        dec_keys[51] = self.modular_inverse(subkeys[3])

        # Reverse and rearrange the other subkeys.
        for i in range(7):
            dec_keys[42 - i * 6] = subkeys[6 * i + 4]
            dec_keys[43 - i * 6] = subkeys[6 * i + 5]
            dec_keys[44 - i * 6] = self.modular_inverse(subkeys[6 * i])
            dec_keys[45 - i * 6] = -subkeys[6 * i + 2] & MAX_VALUE
            dec_keys[46 - i * 6] = -subkeys[6 * i + 1] & MAX_VALUE
            dec_keys[47 - i * 6] = self.modular_inverse(subkeys[6 * i + 3])

        # Initial round keys.
        dec_keys[4] = subkeys[48]
        dec_keys[5] = subkeys[49]
        dec_keys[0] = self.modular_inverse(subkeys[50])
        dec_keys[1] = -subkeys[51] & MAX_VALUE
        dec_keys[2] = -subkeys[49] & MAX_VALUE
        dec_keys[3] = self.modular_inverse(subkeys[48])
        
        return dec_keys

    #####################################
    ### Encrypt and Decrypt Functions ###
    #####################################

    # Function: execute_idea_for_encryption
    # Encrypts a 64-bit block using 8 rounds of operations and a final mixing step.
    def execute_idea_for_encryption(self, plain_text, keys):
        block1 = (plain_text >> (BLOCK_SIZE_BITS - SEGMENT_SIZE_BITS)) & MAX_VALUE
        block2 = (plain_text >> (BLOCK_SIZE_BITS // 2)) & MAX_VALUE
        block3 = (plain_text >> SEGMENT_SIZE_BITS) & MAX_VALUE
        block4 = plain_text & MAX_VALUE
        
        # First 8 rounds.
        for round_index in range(IDEA_ROUNDS):
            round_keys = keys[round_index * 6 : (round_index + 1) * 6]
            
            # Step 1
            block1 = self.multiply_mod(block1, round_keys[0])
            # Step 2
            block2 = (block2 + round_keys[1]) & MAX_VALUE
            # Step 3
            block3 = (block3 + round_keys[2]) & MAX_VALUE
            # Step 4
            block4 = self.multiply_mod(block4, round_keys[3])
            # Step 5
            xor1 = block1 ^ block3
            # Step 6
            xor2 = block2 ^ block4
            # Step 7
            xor1 = self.multiply_mod(xor1, round_keys[4])
            # Step 8
            xor2 = (xor2 + xor1) & MAX_VALUE
            # Step 9
            xor2 = self.multiply_mod(xor2, round_keys[5])
            # Step 10
            xor1 = (xor1 + xor2) & MAX_VALUE

            block1 ^= xor2
            block4 ^= xor1
            xor1 ^= block2
            block2 = xor2 ^ block3
            block3 = xor1

        # Last half round.
        block1 = self.multiply_mod(block1, keys[48])
        block2 = (block3 + keys[49]) & MAX_VALUE
        block3 = (block2 + keys[50]) & MAX_VALUE
        block4 = self.multiply_mod(block4, keys[51])
        
        return (block1 << (BLOCK_SIZE_BITS - SEGMENT_SIZE_BITS)) | (block2 << BLOCK_SIZE_BITS // 2) | (block3 << SEGMENT_SIZE_BITS) | block4

    # Function: execute_idea_for_decryption
    # Decrypts a 64-bit block using 8 rounds of operations and a final mixing step.
    def execute_idea_for_decryption(self, cipher_text, keys):
        block1 = (cipher_text >> (BLOCK_SIZE_BITS - SEGMENT_SIZE_BITS)) & MAX_VALUE
        block2 = (cipher_text >> (BLOCK_SIZE_BITS // 2)) & MAX_VALUE
        block3 = (cipher_text >> SEGMENT_SIZE_BITS) & MAX_VALUE
        block4 = cipher_text & MAX_VALUE

        # First 8 rounds.
        for round_index in range(IDEA_ROUNDS):
            round_keys = keys[round_index * 6 : (round_index + 1) * 6]
            
            # Step 1
            block1 = self.multiply_mod(block1, round_keys[0])
            # Step 2
            block2 = (block2 + round_keys[1]) & MAX_VALUE
            # Step 3
            block3 = (block3 + round_keys[2]) & MAX_VALUE
            # Step 4
            block4 = self.multiply_mod(block4, round_keys[3])
            # Step 5
            xor1 = block1 ^ block3
            # Step 6
            xor2 = block2 ^ block4
            # Step 7
            xor1 = self.multiply_mod(xor1, round_keys[4])
            # Step 8
            xor2 = (xor2 + xor1) & MAX_VALUE
            # Step 9
            xor2 = self.multiply_mod(xor2, round_keys[5])
            # Step 10
            xor1 = (xor1 + xor2) & MAX_VALUE

            block1 ^= xor2
            block4 ^= xor1
            xor1 ^= block2
            block2 = xor2 ^ block3
            block3 = xor1

        # Last half round.
        block1 = self.multiply_mod(block1, keys[48])
        block2 = (block3 + keys[49]) & MAX_VALUE
        block3 = (block2 + keys[50]) & MAX_VALUE
        block4 = self.multiply_mod(block4, keys[51])
        
        return (block1 << (BLOCK_SIZE_BITS - SEGMENT_SIZE_BITS)) | (block2 << BLOCK_SIZE_BITS // 2) | (block3 << SEGMENT_SIZE_BITS) | block4
    
    #########################################
    ### Output Feedback (OFB) Mode Logic ###
    #########################################

    # Function: idea_ofb_mode
    # Processes data in OFB mode for encryption or decryption.
    def idea_ofb_mode(self, iv, data, mode):            
        block_size_bytes = BLOCK_SIZE_BITS // 8

        iv = int.from_bytes(iv, byteorder='big')
        result = bytearray()
    
        for offset in range(0, len(data), block_size_bytes):
            if mode == 'encrypt':
                iv = self.execute_idea_for_encryption(iv, self.encryption_keys)
            else:
                iv = self.execute_idea_for_decryption(iv, self.encryption_keys)
    
            keystream = iv.to_bytes(block_size_bytes, byteorder='big')
    
            block = data[offset : offset + block_size_bytes]
            if len(block) < block_size_bytes:
                block = block.ljust(block_size_bytes, b'\x00')  # Add padding for short blocks.
    
            result.extend(bytes([block_byte ^ keystream_byte for block_byte, keystream_byte in zip(block, keystream)]))
    
        # Return bytes for encryption (to ensure compatibility with other systems).
        return bytes(result)

    ####################################
    ### Modular Arithmetic Functions ###
    ####################################

    # Function: multiply_mod
    # Performs modular multiplication, treating 0 as 65536.
    def multiply_mod(self, a, b):
        if a == 0:
            a = MODULUS - 1
        if b == 0:
            b = MODULUS - 1
        result = (a * b) % MODULUS
        return result if result != (MODULUS - 1) else 0

    # Function: modular_inverse
    # Computes modular inverse of a value modulo 65537.
    def modular_inverse(self, value):
        if value == 0:
            return 0
        return pow(value, MODULUS - 2, MODULUS)