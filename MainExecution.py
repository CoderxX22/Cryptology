import re
import time
from datetime import datetime
from EllipticCurveElGamal import elgamal
from SchnorrProtocol import SchnorrProtocol
from InternationalDataEncryptionAlgorithm import InternationalDataEncryptionAlgorithm
from KeyManager import KeyManager

##############################
### Colors for the console ###
##############################
RED_BG_BLACK = '\033[41;30m'
CYAN_BG_BLACK = '\033[46;30m'
YELLOW_BG_BLACK = '\033[43;30m'
GREEN_BG_BLACK = '\033[42;30m'
BLACK = '\033[0;30m'
UNDERLINE = '\033[4;30m'
RESET = '\033[0m'

#################
### Functions ###
#################

# Function: perform_handshake
# performs a secure handshake between a sender and a receiver by validating Schnorr signatures,
# generating a shared secret using elliptic curve operations, and confirming the shared secret through encrypted message exchange.
def perform_handshake(sender_private_key, sender_public_key, receiver_private_key, receiver_public_key, key_manager):
    # Inform the user that the handshake process is starting
    print(f"\n{GREEN_BG_BLACK}Performing Full Handshake{RESET}")

    # Generate random parameters for the Schnorr protocol
    schnorr_params = key_manager.getRandomSchnorrParameters()
    print(f"{GREEN_BG_BLACK}Schnorr Parameters:{RESET}{BLACK} {schnorr_params}{RESET}")

    # Initialize the Schnorr protocol for the sender and generate the signature
    sender_schnorr = SchnorrProtocol(*schnorr_params)
    sender_schnorr.create_key_pair()
    r_sender, s_sender = sender_schnorr.generate_signature(str(sender_public_key))
    print(f"\n{GREEN_BG_BLACK}Sender Schnorr Signature:{RESET}")
    print(f"{GREEN_BG_BLACK}r:{RESET}{BLACK} {r_sender}{RESET}")
    print(f"{GREEN_BG_BLACK}s:{RESET}{BLACK} {s_sender}{RESET}")

    # Initialize the Schnorr protocol for the receiver and generate the signature
    receiver_schnorr = SchnorrProtocol(*schnorr_params)
    receiver_schnorr.create_key_pair()
    r_receiver, s_receiver = receiver_schnorr.generate_signature(str(receiver_public_key))
    print(f"\n{GREEN_BG_BLACK}Receiver Schnorr Signature:{RESET}")
    print(f"{GREEN_BG_BLACK}r:{RESET}{BLACK} {r_receiver}{RESET}")
    print(f"{GREEN_BG_BLACK}s:{RESET}{BLACK} {s_receiver}{RESET}")

    # Validate the sender's signature using the receiver's Schnorr protocol instance
    sender_signature_valid = receiver_schnorr.validate_signature(
        str(sender_public_key), r_sender, s_sender, sender_schnorr.public_key
    )
    # Validate the receiver's signature using the sender's Schnorr protocol instance
    receiver_signature_valid = sender_schnorr.validate_signature(
        str(receiver_public_key), r_receiver, s_receiver, receiver_schnorr.public_key
    )

    # Check if either of the signatures failed validation
    if not sender_signature_valid or not receiver_signature_valid:
        print(f"{RED_BG_BLACK}Handshake failed: Schnorr signature validation failed!{RESET}")
        return None

    # If signatures are valid, continue with the handshake process
    print(f"\n{GREEN_BG_BLACK}Schnorr signatures validated successfully!{RESET}")
    
    # Simulate processing for shared secret generation
    simulate_processing("Generating shared secret", 3)

    # Compute the shared secrets for both sender and receiver using elliptic curve multiplication
    shared_secret_sender = elgamal.multiply_point_on_curve(sender_private_key, receiver_public_key)
    shared_secret_receiver = elgamal.multiply_point_on_curve(receiver_private_key, sender_public_key)

    # Check if the shared secrets are not identical
    if shared_secret_sender != shared_secret_receiver:
        print(f"{RED_BG_BLACK}Handshake failed: Shared secrets do not match!{RESET}")
        return None

    # Encrypt and decrypt a confirmation message to verify the shared secret
    confirmation_message = "CONFIRM"
    iv = b'\x00' * 8  # Initialization vector for encryption
    sender_encryption_engine = InternationalDataEncryptionAlgorithm(shared_secret_sender[0])
    encrypted_confirmation = InternationalDataEncryptionAlgorithm.idea_ofb_mode(
        sender_encryption_engine, iv, confirmation_message.encode('utf-8'), mode="encrypt"
    )

    receiver_decryption_engine = InternationalDataEncryptionAlgorithm(shared_secret_receiver[0])
    decrypted_confirmation = InternationalDataEncryptionAlgorithm.idea_ofb_mode(
        receiver_decryption_engine, iv, encrypted_confirmation, mode="decrypt"
    )

    # Check if the decrypted confirmation matches the original message
    if decrypted_confirmation.decode('utf-8').rstrip('\x00') == confirmation_message:
        print(f"{GREEN_BG_BLACK}Shared secret confirmed successfully! Handshake complete.{RESET}\n")
        return shared_secret_sender
    else:
        print(f"{RED_BG_BLACK}Shared secret confirmation failed!{RESET}\n")
        return None

# Function: simulate_processing
# Simulates a processing delay.
def simulate_processing(message, delay):
    print(f"{GREEN_BG_BLACK}{message}{RESET}", end="", flush=True)
    for _ in range(delay):
        print(".", end="", flush=True)
        time.sleep(1)
    print()

# Function: get_and_validate_sender_and_receiver_info
# Prompts the user for sender and reciever information, validates the input, and returns the validated data.
def get_and_validate_sender_and_receiver_info():
    ##########################
    ### Sender Information ###
    ##########################
    sender_info = {}
    
    while True:
        # Get and validate name
        print(f"\n{YELLOW_BG_BLACK}Enter sender's name (letters and spaces only):{RESET}", end=" ")
        name = input()
        if re.match(r"^[a-zA-Z\s]+$", name):
            sender_info["name"] = name
            break
        else:
            print(f"{RED_BG_BLACK}Invalid name. Please use only letters and spaces.{RESET}")

    while True:
        # Get and validate ID
        print(f"{YELLOW_BG_BLACK}Enter sender's ID (9-digit number):{RESET}", end=" ")
        id_number = input()
        if re.match(r"^\d{9}$", id_number):
            sender_info["id"] = id_number
            break
        else:
            print(f"{RED_BG_BLACK}Invalid ID. It should be a 9-digit number.{RESET}")

    while True:
        # Get and validate card number
        print(f"{YELLOW_BG_BLACK}Enter card number (16-digit number):{RESET}", end=" ")
        card_number = input()
        if re.match(r"^\d{16}$", card_number):
            sender_info["card_number"] = card_number
            break
        else:
            print(f"{RED_BG_BLACK}Invalid card number. It should be a 16-digit number.{RESET}")

    while True:
        # Get and validate expiry date
        print(f"{YELLOW_BG_BLACK}Enter expiry date (MM/YYYY):{RESET}", end=" ")
        expiry_date = input()
        if re.match(r"^(0[1-9]|1[0-2])/20\d{2}$", expiry_date):
            # Check if the expiry date is in the future
            exp_month, exp_year = map(int, expiry_date.split('/'))
            current_year = datetime.now().year
            current_month = datetime.now().month
            if exp_year > current_year or (exp_year == current_year and exp_month >= current_month):
                sender_info["expiry_date"] = expiry_date
                break
            else:
                print(f"{RED_BG_BLACK}Card is expired. Please enter a valid future expiry date.{RESET}")
        else:
            print(f"{RED_BG_BLACK}Invalid expiry date format. Use MM/YYYY.{RESET}")

    while True:
        # Get and validate CCV
        print(f"{YELLOW_BG_BLACK}Enter CCV (3-digit number):{RESET}", end=" ")
        ccv = input()
        if re.match(r"^\d{3}$", ccv):
            sender_info["ccv"] = ccv
            break
        else:
            print(f"{RED_BG_BLACK}Invalid CCV. It should be a 3-digit number.{RESET}")

    while True:
        # Get and validate amount
        print(f"{YELLOW_BG_BLACK}Enter amount (positive number):{RESET}", end=" ")
        amount = input()
        if amount.isdigit() and int(amount) > 0:
            sender_info["amount"] = amount
            break
        else:
            print(f"{RED_BG_BLACK}Invalid amount. Please enter a positive number.{RESET}")
    
    ############################
    ### Receiver Information ###
    ############################
    receiver_info = {}
    
    while True:
        # Get and validate name
        print(f"\n{YELLOW_BG_BLACK}Enter reciever's name (letters and spaces only):{RESET}", end=" ")
        name = input()
        if re.match(r"^[a-zA-Z\s]+$", name):
            receiver_info["name"] = name
            break
        else:
            print(f"{RED_BG_BLACK}Invalid name. Please use only letters and spaces.{RESET}")

    while True:
        # Get and validate ID
        print(f"{YELLOW_BG_BLACK}Enter reciever's ID (9-digit number):{RESET}", end=" ")
        id_number = input()
        if re.match(r"^\d{9}$", id_number):
            receiver_info["id"] = id_number
            break
        else:
            print(f"{RED_BG_BLACK}Invalid ID. It should be a 9-digit number.{RESET}")
    
    return sender_info, receiver_info

# Function: simulate_payment
# Simulates a secure payment process using ECDH for key exchange,
# IDEA for encryption, and Schnorr for signature generation and validation.
def simulate_payment():    
    ####################
    ### Getting Data ###
    ####################
    
    # Get sender and receiver information
    sender_info, receiver_info = get_and_validate_sender_and_receiver_info()
    
    #######################
    ### Keys Generation ###
    #######################
    
    # Initializing the KeyManager class.
    key_manager = KeyManager()
    
    # Getting random keys for the sender.
    sender_private_key, sender_public_key = key_manager.getPrivateAndPublicKey()
    print(f"{GREEN_BG_BLACK}Sender's private key is:{RESET}{BLACK} {sender_private_key}{RESET}")
    print(f"{GREEN_BG_BLACK}Sender's public key is:{RESET}{BLACK} {sender_public_key}{RESET}")
    
    # Getting random keys for the receiver.
    receiver_private_key, receiver_public_key = key_manager.getPrivateAndPublicKey()
    print(f"{GREEN_BG_BLACK}Receiver's private key is:{RESET}{BLACK} {receiver_private_key}{RESET}")
    print(f"{GREEN_BG_BLACK}Receiver's public key is:{RESET}{BLACK} {receiver_public_key}{RESET}")
    
    # Performing handshake.
    shared_secret = perform_handshake(sender_private_key, sender_public_key, receiver_private_key, receiver_public_key, key_manager)
    if shared_secret == None:
        return
    
    ########################
    ### Encryption Phase ###
    ########################
    
    print(f"\n{GREEN_BG_BLACK}Initiating Payment{RESET}")

    # Encrypt payment data using IDEA
    payment_data = (
        f"data:{sender_info['name']}|{sender_info['id']}|{sender_info['card_number']}|"
        f"{sender_info['expiry_date']}|{sender_info['ccv']}|{sender_info['amount']}"
    )

    iv = b'\x00' * 8
    
    encryption_engine = InternationalDataEncryptionAlgorithm(shared_secret[0])
    encrypted_message = InternationalDataEncryptionAlgorithm.idea_ofb_mode(encryption_engine, iv, payment_data.encode(), mode="encrypt")
    simulate_processing("Encrypting credentials", 5)
    print(f"\n{GREEN_BG_BLACK}Encrypted payment data:{RESET}{BLACK} {encrypted_message.hex()}{RESET}")

    ####################################
    ### Generating Schnorr Signature ###
    ####################################
    
    schnorr_parameters = key_manager.getRandomSchnorrParameters()
    print(f"\n{GREEN_BG_BLACK}Schnorr's Signature for Encrypted Data{RESET}")
    print(f"{GREEN_BG_BLACK}Prime:{RESET}{BLACK} {schnorr_parameters[0]}{RESET}")
    print(f"{GREEN_BG_BLACK}Subgroup Order:{RESET}{BLACK} {schnorr_parameters[1]}{RESET}")
    print(f"{GREEN_BG_BLACK}Generator:{RESET}{BLACK} {schnorr_parameters[2]}{RESET}")
    
    schnorr = SchnorrProtocol(*schnorr_parameters)
    schnorr.create_key_pair()
    r, s = schnorr.generate_signature(payment_data)
    simulate_processing("Generating Schnorr signature", 4)
    print(f"\n{GREEN_BG_BLACK}Schnorr Signature:{RESET}")
    print(f"{GREEN_BG_BLACK}r:{RESET}{BLACK} {r}{RESET}")
    print(f"{GREEN_BG_BLACK}s:{RESET}{BLACK} {s}{RESET}")
    print(f"{GREEN_BG_BLACK}y:{RESET}{BLACK} {schnorr.public_key}{RESET}")

    ########################
    ### Decryption Phase ###
    ########################
    
    print(f"\n{GREEN_BG_BLACK}Receiving Payment{RESET}")

    # Decrypt payment data using IDEA
    decryption_engine = InternationalDataEncryptionAlgorithm(shared_secret[0])
    decrypted_message = InternationalDataEncryptionAlgorithm.idea_ofb_mode(decryption_engine, iv, encrypted_message, mode="decrypt")
    decrypted_message = decrypted_message.decode('utf-8').rstrip('\x00')
    simulate_processing("Decrypting credentials", 5)
    print(f"{GREEN_BG_BLACK}Decrypted payment data:{RESET}{BLACK} {decrypted_message}{RESET}")
    
    ######################################
    ### Schnorr Signature Verification ###
    ######################################
    
    print(f"\n{GREEN_BG_BLACK}Schnorr Verification{RESET}")
    
    simulate_processing("Validating", 4)
    
    schnorr_verifier = SchnorrProtocol(*schnorr_parameters)
    is_valid = schnorr_verifier.validate_signature(decrypted_message, r, s, schnorr.public_key)
    
    if is_valid:
        print(f"{GREEN_BG_BLACK}Schnorr Signature Verification is VALID.{RESET}")
        print(f"{GREEN_BG_BLACK}Payment of {sender_info['amount']} from {sender_info['name']} to {receiver_info['name']} completed.{RESET}\n\n\n")
    else:
        print(f"{RED_BG_BLACK}Schnorr Signature Verification is INVALID.{RESET}")
        print(f"{RED_BG_BLACK}Payment failed: Signature verification unsuccessful.{RESET}\n\n\n")

# Function: show_application_info
# Shows the information about the process in the application.
def show_application_info():
    print(f"{BLACK}Welcome to our Secure Payment Application!{RESET}")
    print(f"{BLACK}This application integrates the {UNDERLINE}International Data Encryption Algorithm (IDEA){RESET}")
    print(f"{BLACK}in {UNDERLINE}Output Feedback (OFB){RESET}{BLACK} mode for secure data encryption and decryption.{RESET}")
    print("")
    print(f"{BLACK}It leverages the {UNDERLINE}Elliptic Curve Diffie-Hellman (EC-DH){RESET}{BLACK} key exchange protocol{RESET}")
    print(f"{BLACK}to generate secure shared secrets for encryption.{RESET}")
    print("")
    print(f"{BLACK}To ensure data integrity and authenticity, we use the {UNDERLINE}Schnorr Signature{RESET}{BLACK} algorithm.{RESET}")
    print(f"{BLACK}This ensures that transactions are both tamper-proof and verifiable.{RESET}")
    print("")
    print(f"{BLACK}Our application provides a comprehensive simulation of secure payment processing,{RESET}")
    print(f"{BLACK}from key generation to encryption, decryption, and signature validation.{RESET}")
    print("")
    print(f"{BLACK}Experience state-of-the-art cryptographic security, designed with simplicity and precision!\n\n{RESET}")


# Function: display_menu
# Displays a menu for the user to choose from.
def display_menu():
    while True:
        print(f"{YELLOW_BG_BLACK}1 >>> Initiating a payment{RESET}")
        print(f"{YELLOW_BG_BLACK}2 >>> Showing application information{RESET}")
        print(f"{YELLOW_BG_BLACK}3 >>> Exit{RESET}")
        choice = input("Your choice: ")

        if choice not in ["1", "2", "3"]:
            print(f"{RED_BG_BLACK}Please choose a valid option.{RESET}")
            continue
        else:
            if choice == "1":
                simulate_payment()
            if choice == "2":
                show_application_info()
            if choice == "3":
                print(f"{YELLOW_BG_BLACK}Exiting.{RESET}")
                break

######################
### Main Execution ###
######################

# Function: main
# The main function that runs the application.
def main():
    print(f"{CYAN_BG_BLACK}#########################{RESET}")
    print(f"{CYAN_BG_BLACK}{UNDERLINE}Payment System Simulation{RESET}")
    print(f"{CYAN_BG_BLACK}#########################{RESET}")
    
    display_menu()
    
main()