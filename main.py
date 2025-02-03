import os
import base64
import random
import itertools
import time
import hashlib
import threading
import numpy as np
from dotenv import load_dotenv
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import logging

# Set up logging
log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'logs')
# Create the logs directory if it doesn't exist
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

log_filename = os.path.join(log_dir, 'app.log')
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.StreamHandler(),  # Logs to console
                        logging.FileHandler(log_filename)  # Logs to file
                    ])

# Load environment variables from .env file
load_dotenv()

# Read the message from the environment variable MESSAGE, or use "Hello World!" if not found
original_message = os.getenv("MESSAGE", "Hello World!")

# Generate RSA keys
def generate_rsa_keys():
    logging.info("Generating RSA keys...")
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    logging.debug("RSA keys generated.")
    return private_key, public_key

# AES encryption and decryption functions
def aes_encrypt(message, key):
    logging.debug("AES encrypting message...")
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    logging.debug("Message encrypted with AES.")
    return cipher.nonce + tag + ciphertext

def aes_decrypt(encrypted_message, key):
    logging.debug("AES decrypting message...")
    nonce, tag, ciphertext = encrypted_message[:16], encrypted_message[16:32], encrypted_message[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    decrypted_message = cipher.decrypt_and_verify(ciphertext, tag).decode()
    logging.debug("Message decrypted with AES.")
    return decrypted_message

# RSA encryption and decryption with signature verification
def rsa_encrypt(message, public_key):
    logging.debug("RSA encrypting message...")
    public_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    logging.debug("Message encrypted with RSA.")
    return encrypted_message

def rsa_decrypt(encrypted_message, private_key):
    logging.debug("RSA decrypting message...")
    private_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    logging.debug("Message decrypted with RSA.")
    return decrypted_message

def rsa_sign(message, private_key):
    logging.debug("Signing message with RSA...")
    private_key = RSA.import_key(private_key)
    h = SHA256.new(message.encode())
    signer = pkcs1_15.new(private_key)
    signature = signer.sign(h)
    logging.debug("Message signed with RSA.")
    return signature

def rsa_verify(message, signature, public_key):
    logging.debug("Verifying RSA signature...")
    public_key = RSA.import_key(public_key)
    h = SHA256.new(message.encode())
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(h, signature)
        logging.debug("RSA signature verified.")
        return True
    except (ValueError, TypeError):
        logging.error("RSA signature verification failed.")
        return False

# Base64 encoding with multiple iterations
def base64_encode(message):
    logging.debug("Base64 encoding message...")
    encoded_message = message
    for i in range(10):  # Increased the number of iterations for more complexity
        encoded_message = base64.b64encode(encoded_message.encode()).decode()
    logging.debug("Message Base64 encoded.")
    return encoded_message

# Multithreaded permutation generation based on the message
def generate_permutations(message):
    logging.debug("Generating permutations...")
    result = []
    for length in range(2, len(message) + 1):
        result.extend(itertools.permutations(message, length))
    logging.debug("Permutations generated.")
    return result

def brute_force_permutations(message):
    return generate_permutations(message)

# Perform complex checksum calculations with NumPy and cryptographic hash
def complex_checksum_calculation(message):
    logging.debug("Calculating checksum...")
    data = np.array([ord(c) for c in message], dtype=np.int64)
    checksum_part = np.sum(np.power(data, 2)) + np.dot(data, np.random.randint(1, 1000, len(data)))
    checksum_hash = SHA256.new(data.tobytes()).hexdigest()
    logging.debug("Checksum calculated.")
    return checksum_part, checksum_hash

# Simulate cryptographic transformations on the message
def cryptographic_message_processing(message):
    logging.debug("Processing message with cryptographic transformations...")
    processed_message = ""
    for char in message:
        transformed_char = chr((ord(char) * random.randint(1, 15) + random.randint(0, 255)) % 256)
        processed_message += transformed_char
        time.sleep(0.1)
    logging.debug("Message processing complete.")
    return processed_message

# Perform a series of encryptions and modifications on the message
def perform_encryption_process(message, private_key, public_key):
    logging.debug("Performing encryption process...")
    # Step 1: RSA encryption and decryption
    encrypted_message_rsa = rsa_encrypt(message, public_key)
    message = rsa_decrypt(encrypted_message_rsa, private_key)

    # Step 2: Apply multiple layers of AES encryption and decryption
    aes_key1 = get_random_bytes(16)
    aes_key2 = get_random_bytes(16)
    encrypted_message_aes1 = aes_encrypt(message, aes_key1)
    message = aes_decrypt(encrypted_message_aes1, aes_key1)

    encrypted_message_aes2 = aes_encrypt(message, aes_key2)
    message = aes_decrypt(encrypted_message_aes2, aes_key2)

    # Step 3: Perform multiple base64 encodings
    message = base64_encode(message)

    # Step 4: Calculate checksum and modify the message with it
    checksum_value, checksum_hash = complex_checksum_calculation(message)
    message = message + checksum_hash[:16]  # Modify the message with checksum

    # Step 5: Perform cryptographic transformations on the message
    message = cryptographic_message_processing(message)

    # Step 6: Sign the modified message and verify the signature
    signature = rsa_sign(message, private_key)
    rsa_signature_valid = rsa_verify(message, signature, public_key)
    
    logging.info("\nEncryption process complete.")
    return message, rsa_signature_valid

# Main function to execute all operations and modify the original message
def main():
    private_key, public_key = generate_rsa_keys()

    # Perform the complex encryption process on the message
    message = original_message
    modified_message, rsa_signature_valid = perform_encryption_process(message, private_key, public_key)

    # Start permutation generation in a separate thread
    permutation_thread = threading.Thread(target=brute_force_permutations, args=(modified_message,))
    permutation_thread.start()
    permutation_thread.join()

    # Decrypt the modified message to get the original message (Hello World!)
    # Apply all transformations in reverse
    decrypted_message = rsa_decrypt(rsa_encrypt(modified_message, public_key), private_key)
    aes_key1 = get_random_bytes(16)
    aes_key2 = get_random_bytes(16)
    decrypted_message = aes_decrypt(aes_encrypt(decrypted_message, aes_key1), aes_key1)
    decrypted_message = aes_decrypt(aes_encrypt(decrypted_message, aes_key2), aes_key2)
    decrypted_message = base64.b64decode(decrypted_message).decode()

    # Output the final decrypted "Hello World!"
    logging.info("\nFinal decrypted message: %s", decrypted_message)

# Run the main function
if __name__ == "__main__":
    main()