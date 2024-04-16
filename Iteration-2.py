import tenseal as ts
import base64
import zlib
import logging
import sqlite3
import os


DATABASE_PATH = '/Users/lukedawson1156/Desktop/Yr 3 Project/Development Project/Iterations/Database/fingerprints.db'
KEYS_FILE_PATH = '/Users/lukedawson1156/Desktop/Yr 3 Project/Development Project/Iterations/Database/Keys/print-key.bin'

logging.basicConfig(
    level=logging.DEBUG, 
    filename='/Users/lukedawson1156/Desktop/Yr 3 Project/Development Project/Iterations/Logs/biometric_system_1.log',
    filemode='a',
    format='%(asctime)s - %(levelname)s - %(message)s',
    )

def initialize_database():
    logging.debug("Initalising Database")
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS fingerprints (
                        user_id TEXT PRIMARY KEY,
                        encrypted_data BLOB
                    )''')
    conn.commit()
    conn.close()

def save_to_database(user_id, encrypted_data):
    logging.debug(f"Saving to database for user_id: {user_id}")
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    # Ensure encrypted_data is bytes; if it's a string, encode it to bytes
    if isinstance(encrypted_data, str):
        encrypted_data = encrypted_data.encode()
    # Compress and then base64 encode the encrypted_data before storing it in the database
    compressed_data = zlib.compress(encrypted_data)
    cursor.execute("REPLACE INTO fingerprints (user_id, encrypted_data) VALUES (?, ?)",
                   (user_id, compressed_data))
    conn.commit()
    conn.close()


def load_from_database(user_id):
    logging.debug(f"Loading from database for user_id: {user_id}.")
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT encrypted_data FROM fingerprints WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        try:
            decompressed_data = zlib.decompress(row[0])
            return decompressed_data
        except zlib.error as e:
            logging.error("Decompression error: %s", str(e))
        except Exception as e:
            logging.error("Error handling data from database: %s", str(e))
    else:
        logging.info("No encrypted data found for user ID: %s", user_id)
    return None

def print_all_user_ids():
    logging.debug("Printing all user IDs.")
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM fingerprints")
    user_ids = cursor.fetchall()
    conn.close()
    if user_ids:
        print("User IDs currently stored in the database:")
        for user_id in user_ids:
            print(user_id[0])
    else:
        print("No fingerprints are currently stored in the database.")

def save_keys(context):
    logging.debug("Attempting to save the context with the secret key.")
    with open(KEYS_FILE_PATH, 'wb') as f:
        f.write(context.serialize(save_secret_key=True))
    logging.info("Context with secret key saved successfully.")

def load_keys():
    logging.debug("Attempting to load the context with the secret key.")
    with open(KEYS_FILE_PATH, 'rb') as f:
        context = ts.context_from(f.read())
    if context.has_secret_key():
        logging.info("Context with secret key loaded successfully.")
    else:
        logging.error("Failed to load the secret key from the context.")
    return context




# Create a new context and save it
context = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
context.generate_galois_keys()
context.global_scale = 2**40
save_keys(context)

# Now, try to load it immediately
loaded_context = load_keys()


def create_context_and_keys():
    if os.path.exists(KEYS_FILE_PATH):
        logging.info("Key file found. Attempting to load context.")
        return load_keys()
    else:
        logging.info("Key file not found. Creating new context and keys.")
        context = ts.context(ts.SCHEME_TYPE.CKKS, poly_modulus_degree=8192, coeff_mod_bit_sizes=[60, 40, 40, 60])
        context.generate_galois_keys()
        context.global_scale = 2**40
        
        # Check if the context is private and has a secret key
        if context.is_private():
            logging.info("The context is private and contains a secret key.")
            save_keys(context)
        else:
            logging.error("The context is public and does not contain a secret key.")
            raise ValueError("Failed to create a secret key.")
        
        return context

def preprocess_biometric_data(data):
    logging.debug(f"Preprocessing biometric data: {data}.")
    min_val = 0
    max_val = 100
    normalized_data = [(float(i) - min_val) / (max_val - min_val) for i in data]
    print("Preprocessed data:", normalized_data)
    return normalized_data

def encrypt_biometric_data(data, context):
    logging.debug("Encrypting biometric data.")
    encrypted_data = ts.ckks_vector(context, data)
    # Make sure the serialized data is in bytes format
    serialized_data = encrypted_data.serialize()
    return serialized_data  # This should be a bytes object


def decrypt_data(encrypted_data, context):
    logging.debug("Decrypting data.")
    try:
        encrypted_vector = ts.lazy_ckks_vector_from(encrypted_data)
        encrypted_vector.link_context(context)
        decrypted_data = encrypted_vector.decrypt()
        logging.info("Data decrypted successfully.")
        return [round(num, 2) for num in decrypted_data]
    except Exception as e:
        logging.exception("Failed to decrypt data.")
        raise

def compare_fingerprints(stored, current, threshold=95):
    # Assuming stored and current are lists of decrypted floating point values
    if not stored or not current:
        return False
    matched = sum(1 for x, y in zip(stored, current) if abs(x - y) <= 0.05)  # Adjust 0.05 based on your precision needs
    total = len(stored)
    similarity = (matched / total) * 100
    return similarity >= threshold


def input_biometric_data():
    logging.debug("Inputting biometric data.")
    print("Please enter your biometric data as 5 numbers separated by space (each number represents a biometric point):")
    data = list(map(float, input().split()))
    if len(data) != 5:
        print("Invalid input. Please enter exactly 5 numbers.")
        return input_biometric_data()
    return data

def user_interaction_flow(context):
    logging.debug("Starting user interaction flow.")
    print_all_user_ids()
    action = input("Choose an action: \n1. Add new ID \n2. Log in with existing ID \n3. Exit \nYour choice (1/2/3): ").strip()

    if action == "1":
        user_id = input("Enter a User ID for your new fingerprint: ").strip()
        fingerprint_data = input_biometric_data()
        preprocessed_data = preprocess_biometric_data(fingerprint_data)
        encrypted_data = encrypt_biometric_data(preprocessed_data, context)
        save_to_database(user_id, encrypted_data)  # Save the new fingerprint to the SQLite database
        print("New fingerprint stored successfully. Your data has been encrypted.")

    elif action == "2":
        user_id = input("Please enter your User ID: ").strip()
        stored_encrypted_data = load_from_database(user_id)  # Load the stored fingerprint data from the SQLite database

        if stored_encrypted_data:
            print("Please enter your biometric data for verification:")
            fingerprint_data = input_biometric_data()
            preprocessed_data = preprocess_biometric_data(fingerprint_data)
            encrypted_data = encrypt_biometric_data(preprocessed_data, context)
            current_fingerprint_data = decrypt_data(encrypted_data, context)
            stored_fingerprint_data = decrypt_data(stored_encrypted_data, context)

            if compare_fingerprints(stored_fingerprint_data, current_fingerprint_data):
                print("Biometrics approved.")
            else:
                print("Biometrics denied.")
        else:
            print("No user ID found in the database.")

    elif action == "3":
        print("Exiting the system.")
    else:
        print("Invalid response. Please enter '1', '2', or '3'.")



if __name__ == "__main__":
    try:
        # Initialize the database
        initialize_database()

        # Create or load the context and keys
        context = create_context_and_keys()

        # Proceed with the user interaction flow
        user_interaction_flow(context)

    except Exception as e:
        logging.exception(f"An error occurred during the main execution: {e}")
        print(f"An error occurred: {e}")

    # Any additional main-level code would go here
    print("Program finished executing.")

