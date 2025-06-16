import tkinter as tk
from tkinter import messagebox, scrolledtext
from datetime import datetime
import re
import time
import threading
from EllipticCurveElGamal import elgamal
from SchnorrProtocol import SchnorrProtocol
from InternationalDataEncryptionAlgorithm import InternationalDataEncryptionAlgorithm
from KeyManager import KeyManager


class PaymentApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Payment Application")
        self.key_manager = KeyManager()

        self.build_ui()

    def build_ui(self):
        self.form_frame = tk.Frame(self.root)
        self.form_frame.pack(pady=10)

        self.build_sender_fields()
        self.build_receiver_fields()

        self.submit_btn = tk.Button(self.root, text="Submit Payment", command=self.run_simulation)
        self.submit_btn.pack(pady=5)

        self.info_btn = tk.Button(self.root, text="Application Info", command=self.show_application_info)
        self.info_btn.pack(pady=5)

        self.output = scrolledtext.ScrolledText(self.root, width=80, height=30)
        self.output.pack(pady=10)

    def build_sender_fields(self):
        self.sender_entries = {}
        tk.Label(self.form_frame, text="Sender Information").grid(row=0, column=0, columnspan=2)
        labels = ["Name", "ID", "Card Number", "Expiry Date (MM/YYYY)", "CCV", "Amount"]
        for i, label in enumerate(labels):
            tk.Label(self.form_frame, text=label).grid(row=i+1, column=0, sticky='e')
            entry = tk.Entry(self.form_frame)
            entry.grid(row=i+1, column=1)
            self.sender_entries[label] = entry

    def build_receiver_fields(self):
        self.receiver_entries = {}
        base_row = 8
        tk.Label(self.form_frame, text="Receiver Information").grid(row=base_row, column=0, columnspan=2)
        labels = ["Name", "ID"]
        for i, label in enumerate(labels):
            tk.Label(self.form_frame, text=label).grid(row=base_row+i+1, column=0, sticky='e')
            entry = tk.Entry(self.form_frame)
            entry.grid(row=base_row+i+1, column=1)
            self.receiver_entries[label] = entry

    def show_application_info(self):
        info = (
            "This app uses:\n"
            "- IDEA in OFB mode for encryption\n"
            "- ECC-based ElGamal for key exchange\n"
            "- Schnorr signatures for authenticity\n"
        )
        messagebox.showinfo("Application Info", info)

    def run_simulation(self):
        threading.Thread(target=self.simulate_payment).start()

    def simulate_payment(self):
        self.output.delete(1.0, tk.END)
        sender_info = self.validate_sender_info()
        receiver_info = self.validate_receiver_info()
        if not sender_info or not receiver_info:
            return

        self.write("Generating keys...")
        s_priv, s_pub = self.key_manager.getPrivateAndPublicKey()
        r_priv, r_pub = self.key_manager.getPrivateAndPublicKey()

        shared_secret = self.perform_handshake(s_priv, s_pub, r_priv, r_pub)
        if not shared_secret:
            return

        self.write("\nInitiating Payment")
        data = f"data:{sender_info['name']}|{sender_info['id']}|{sender_info['card_number']}|{sender_info['expiry_date']}|{sender_info['ccv']}|{sender_info['amount']}"
        iv = b'\x00' * 8
        engine = InternationalDataEncryptionAlgorithm(shared_secret[0])
        encrypted = InternationalDataEncryptionAlgorithm.idea_ofb_mode(engine, iv, data.encode(), mode="encrypt")

        self.simulate_processing("Encrypting credentials", 5)
        self.write(f"\nEncrypted: {encrypted.hex()}")

        schnorr_params = self.key_manager.getRandomSchnorrParameters()
        schnorr = SchnorrProtocol(*schnorr_params)
        schnorr.create_key_pair()
        r, s = schnorr.generate_signature(data)
        self.simulate_processing("Generating Schnorr signature", 4)
        self.write(f"\nSchnorr Signature: r={r}, s={s}, y={schnorr.public_key}")

        dec_engine = InternationalDataEncryptionAlgorithm(shared_secret[0])
        decrypted = InternationalDataEncryptionAlgorithm.idea_ofb_mode(dec_engine, iv, encrypted, mode="decrypt")
        decrypted = decrypted.decode('utf-8').rstrip('\x00')
        self.simulate_processing("Decrypting credentials", 5)
        self.write(f"\nDecrypted: {decrypted}")

        verifier = SchnorrProtocol(*schnorr_params)
        valid = verifier.validate_signature(decrypted, r, s, schnorr.public_key)
        self.simulate_processing("Verifying signature", 3)
        if valid:
            self.write(f"\nVALID Signature. Payment of {sender_info['amount']} from {sender_info['name']} to {receiver_info['name']} complete.")
        else:
            self.write("\nINVALID Signature. Payment failed.")

    def validate_sender_info(self):
        info = {}
        key_map = {
            "Name": "name",
            "ID": "id",
            "Card Number": "card_number",
            "Expiry Date (MM/YYYY)": "expiry_date",
            "CCV": "ccv",
            "Amount": "amount"
        }
        patterns = {
            "Name": r"^[a-zA-Z\s]+$",
            "ID": r"^\d{9}$",
            "Card Number": r"^\d{16}$",
            "Expiry Date (MM/YYYY)": r"^(0[1-9]|1[0-2])/20\d{2}$",
            "CCV": r"^\d{3}$",
            "Amount": r"^\d+$"
        }
        for label, entry in self.sender_entries.items():
            value = entry.get().strip()
            if not re.match(patterns[label], value):
                messagebox.showerror("Invalid Input", f"Invalid sender {label}")
                return None
            if label == "Expiry Date (MM/YYYY)":
                month, year = map(int, value.split('/'))
                now = datetime.now()
                if year < now.year or (year == now.year and month < now.month):
                    messagebox.showerror("Expired", "Card is expired")
                    return None
            info[key_map[label]] = value
        return info

    def validate_receiver_info(self):
        info = {}
        for label, entry in self.receiver_entries.items():
            value = entry.get().strip()
            if not re.match(r"^[a-zA-Z\s]+$" if label == "Name" else r"^\d{9}$", value):
                messagebox.showerror("Invalid Input", f"Invalid receiver {label}")
                return None
            info[label.lower()] = value
        return info

    def perform_handshake(self, s_priv, s_pub, r_priv, r_pub):
        self.write("\nPerforming handshake")
        schnorr_params = self.key_manager.getRandomSchnorrParameters()
        s_schnorr = SchnorrProtocol(*schnorr_params)
        s_schnorr.create_key_pair()
        r1, s1 = s_schnorr.generate_signature(str(s_pub))

        r_schnorr = SchnorrProtocol(*schnorr_params)
        r_schnorr.create_key_pair()
        r2, s2 = r_schnorr.generate_signature(str(r_pub))

        if not r_schnorr.validate_signature(str(s_pub), r1, s1, s_schnorr.public_key):
            self.write("\nSender Schnorr validation failed")
            return None
        if not s_schnorr.validate_signature(str(r_pub), r2, s2, r_schnorr.public_key):
            self.write("\nReceiver Schnorr validation failed")
            return None

        shared1 = elgamal.multiply_point_on_curve(s_priv, r_pub)
        shared2 = elgamal.multiply_point_on_curve(r_priv, s_pub)
        if shared1 != shared2:
            self.write("\nShared secret mismatch")
            return None

        self.write("\nHandshake complete and shared secret confirmed")
        return shared1

    def simulate_processing(self, msg, delay):
        for i in range(delay):
            self.write(f"{msg}{'.' * (i + 1)}")
            time.sleep(1)

    def write(self, text):
        self.output.insert(tk.END, text + '\n')
        self.output.see(tk.END)


if __name__ == '__main__':
    root = tk.Tk()
    app = PaymentApp(root)
    root.mainloop()
