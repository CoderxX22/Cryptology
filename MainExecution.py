import re
import time
from datetime import datetime
from EllipticCurveElGamal import elgamal
from SchnorrProtocol import SchnorrProtocol
from InternationalDataEncryptionAlgorithm import InternationalDataEncryptionAlgorithm
from KeyManager import KeyManager


# --- Functions ---

def perform_handshake(sender_private_key, sender_public_key, receiver_private_key, receiver_public_key, key_manager):
    print("\nPerforming Full Handshake")

    schnorr_params = key_manager.getRandomSchnorrParameters()
    print(f"Schnorr Parameters: {schnorr_params}")

    sender_schnorr = SchnorrProtocol(*schnorr_params)
    sender_schnorr.create_key_pair()
    r_sender, s_sender = sender_schnorr.generate_signature(str(sender_public_key))
    print("\nSender Schnorr Signature:")
    print(f"r: {r_sender}")
    print(f"s: {s_sender}")

    receiver_schnorr = SchnorrProtocol(*schnorr_params)
    receiver_schnorr.create_key_pair()
    r_receiver, s_receiver = receiver_schnorr.generate_signature(str(receiver_public_key))
    print("\nReceiver Schnorr Signature:")
    print(f"r: {r_receiver}")
    print(f"s: {s_receiver}")

    sender_signature_valid = receiver_schnorr.validate_signature(
        str(sender_public_key), r_sender, s_sender, sender_schnorr.public_key
    )
    receiver_signature_valid = sender_schnorr.validate_signature(
        str(receiver_public_key), r_receiver, s_receiver, receiver_schnorr.public_key
    )

    if not sender_signature_valid or not receiver_signature_valid:
        print("Handshake failed: Schnorr signature validation failed!")
        return None

    print("\nSchnorr signatures validated successfully!")
    simulate_processing("Generating shared secret", 3)

    shared_secret_sender = elgamal.multiply_point_on_curve(sender_private_key, receiver_public_key)
    shared_secret_receiver = elgamal.multiply_point_on_curve(receiver_private_key, sender_public_key)

    if shared_secret_sender != shared_secret_receiver:
        print("Handshake failed: Shared secrets do not match!")
        return None

    confirmation_message = "CONFIRM"
    iv = b'\x00' * 8
    sender_encryption_engine = InternationalDataEncryptionAlgorithm(shared_secret_sender[0])
    encrypted_confirmation = InternationalDataEncryptionAlgorithm.idea_ofb_mode(
        sender_encryption_engine, iv, confirmation_message.encode('utf-8'), mode="encrypt"
    )

    receiver_decryption_engine = InternationalDataEncryptionAlgorithm(shared_secret_receiver[0])
    decrypted_confirmation = InternationalDataEncryptionAlgorithm.idea_ofb_mode(
        receiver_decryption_engine, iv, encrypted_confirmation, mode="decrypt"
    )

    if decrypted_confirmation.decode('utf-8').rstrip('\x00') == confirmation_message:
        print("Shared secret confirmed successfully! Handshake complete.\n")
        return shared_secret_sender
    else:
        print("Shared secret confirmation failed!\n")
        return None


def simulate_processing(message, delay):
    print(message, end="", flush=True)
    for _ in range(delay):
        print(".", end="", flush=True)
        time.sleep(1)
    print()


def get_and_validate_sender_and_receiver_info():
    sender_info = {}
    while True:
        name = input("\nEnter sender's name (letters and spaces only): ")
        if re.match(r"^[a-zA-Z\s]+$", name):
            sender_info["name"] = name
            break
        else:
            print("Invalid name. Please use only letters and spaces.")

    while True:
        id_number = input("Enter sender's ID (9-digit number): ")
        if re.match(r"^\d{9}$", id_number):
            sender_info["id"] = id_number
            break
        else:
            print("Invalid ID. It should be a 9-digit number.")

    while True:
        card_number = input("Enter card number (16-digit number): ")
        if re.match(r"^\d{16}$", card_number):
            sender_info["card_number"] = card_number
            break
        else:
            print("Invalid card number. It should be a 16-digit number.")

    while True:
        expiry_date = input("Enter expiry date (MM/YYYY): ")
        if re.match(r"^(0[1-9]|1[0-2])/20\d{2}$", expiry_date):
            exp_month, exp_year = map(int, expiry_date.split('/'))
            current_year = datetime.now().year
            current_month = datetime.now().month
            if exp_year > current_year or (exp_year == current_year and exp_month >= current_month):
                sender_info["expiry_date"] = expiry_date
                break
            else:
                print("Card is expired. Please enter a valid future expiry date.")
        else:
            print("Invalid expiry date format. Use MM/YYYY.")

    while True:
        ccv = input("Enter CCV (3-digit number): ")
        if re.match(r"^\d{3}$", ccv):
            sender_info["ccv"] = ccv
            break
        else:
            print("Invalid CCV. It should be a 3-digit number.")

    while True:
        amount = input("Enter amount (positive number): ")
        if amount.isdigit() and int(amount) > 0:
            sender_info["amount"] = amount
            break
        else:
            print("Invalid amount. Please enter a positive number.")

    receiver_info = {}
    while True:
        name = input("\nEnter receiver's name (letters and spaces only): ")
        if re.match(r"^[a-zA-Z\s]+$", name):
            receiver_info["name"] = name
            break
        else:
            print("Invalid name. Please use only letters and spaces.")

    while True:
        id_number = input("Enter receiver's ID (9-digit number): ")
        if re.match(r"^\d{9}$", id_number):
            receiver_info["id"] = id_number
            break
        else:
            print("Invalid ID. It should be a 9-digit number.")

    return sender_info, receiver_info


def simulate_payment():
    sender_info, receiver_info = get_and_validate_sender_and_receiver_info()

    key_manager = KeyManager()
    sender_private_key, sender_public_key = key_manager.getPrivateAndPublicKey()
    print(f"Sender's private key is: {sender_private_key}")
    print(f"Sender's public key is: {sender_public_key}")

    receiver_private_key, receiver_public_key = key_manager.getPrivateAndPublicKey()
    print(f"Receiver's private key is: {receiver_private_key}")
    print(f"Receiver's public key is: {receiver_public_key}")

    shared_secret = perform_handshake(sender_private_key, sender_public_key, receiver_private_key, receiver_public_key,
                                      key_manager)
    if shared_secret is None:
        return

    print("\nInitiating Payment")

    payment_data = (
        f"data:{sender_info['name']}|{sender_info['id']}|{sender_info['card_number']}|"
        f"{sender_info['expiry_date']}|{sender_info['ccv']}|{sender_info['amount']}"
    )

    iv = b'\x00' * 8
    encryption_engine = InternationalDataEncryptionAlgorithm(shared_secret[0])
    encrypted_message = InternationalDataEncryptionAlgorithm.idea_ofb_mode(encryption_engine, iv, payment_data.encode(),
                                                                           mode="encrypt")
    simulate_processing("Encrypting credentials", 5)
    print(f"\nEncrypted payment data: {encrypted_message.hex()}")

    schnorr_parameters = key_manager.getRandomSchnorrParameters()
    print("\nSchnorr's Signature for Encrypted Data")
    print(f"Prime: {schnorr_parameters[0]}")
    print(f"Subgroup Order: {schnorr_parameters[1]}")
    print(f"Generator: {schnorr_parameters[2]}")

    schnorr = SchnorrProtocol(*schnorr_parameters)
    schnorr.create_key_pair()
    r, s = schnorr.generate_signature(payment_data)
    simulate_processing("Generating Schnorr signature", 4)
    print(f"\nSchnorr Signature:")
    print(f"r: {r}")
    print(f"s: {s}")
    print(f"y: {schnorr.public_key}")

    print("\nReceiving Payment")
    decryption_engine = InternationalDataEncryptionAlgorithm(shared_secret[0])
    decrypted_message = InternationalDataEncryptionAlgorithm.idea_ofb_mode(decryption_engine, iv, encrypted_message,
                                                                           mode="decrypt")
    decrypted_message = decrypted_message.decode('utf-8').rstrip('\x00')
    simulate_processing("Decrypting credentials", 5)
    print(f"Decrypted payment data: {decrypted_message}")

    print("\nSchnorr Verification")
    simulate_processing("Validating", 4)
    schnorr_verifier = SchnorrProtocol(*schnorr_parameters)
    is_valid = schnorr_verifier.validate_signature(decrypted_message, r, s, schnorr.public_key)

    if is_valid:
        print(f"Schnorr Signature Verification is VALID.")
        print(
            f"Payment of {sender_info['amount']} from {sender_info['name']} to {receiver_info['name']} completed.\n\n\n")
    else:
        print("Schnorr Signature Verification is INVALID.")
        print("Payment failed: Signature verification unsuccessful.\n\n\n")


def show_application_info():
    print("Welcome to our Secure Payment Application!")
    print("This application integrates the International Data Encryption Algorithm (IDEA)")
    print("in Output Feedback (OFB) mode for secure data encryption and decryption.")
    print("")
    print("It leverages the Elliptic Curve Diffie-Hellman (EC-DH) key exchange protocol")
    print("to generate secure shared secrets for encryption.")
    print("")
    print("To ensure data integrity and authenticity, we use the Schnorr Signature algorithm.")
    print("This ensures that transactions are both tamper-proof and verifiable.")
    print("")
    print("Our application provides a comprehensive simulation of secure payment processing,")
    print("from key generation to encryption, decryption, and signature validation.")
    print("")
    print("Experience state-of-the-art cryptographic security, designed with simplicity and precision!\n\n")


def display_menu():
    while True:
        print("1 >>> Initiating a payment")
        print("2 >>> Showing application information")
        print("3 >>> Exit")
        choice = input("Your choice: ")

        if choice not in ["1", "2", "3"]:
            print("Please choose a valid option.")
            continue
        else:
            if choice == "1":
                simulate_payment()
            elif choice == "2":
                show_application_info()
            elif choice == "3":
                print("Exiting.")
                break


def main():
    print("#########################")
    print("Payment System Simulation")
    print("#########################")
    display_menu()


main()
