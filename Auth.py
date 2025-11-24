import bcrypt
import os

USER_DATA_FILE = "users.txt"

def hash_password(plaintext_password):
    password_bytes= plaintext_password.encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password


def verify_password(plaintext_password, hashed_password):
    password_bytes = plaintext_password.encode('utf-8')
    result=bcrypt.checkpw(password_bytes, hashed_password)
    return result



def register_user(username, password):
    if os.path.exists(USER_DATA_FILE):
        with open(USER_DATA_FILE, "r") as file:
            for line in file:
                stored_username, _ = line.strip().split(":")
                if stored_username == username:
                    print("Username already exists. Please choose a different username.")
                    return False

    hashed_password = hash_password(password)

    with open(USER_DATA_FILE, "a") as file:
        file.write(f"{username}:{hashed_password.decode('utf-8')}\n")
    print("User registered successfully.")
    return True

def user_exists(username):
    if not os.path.exists(USER_DATA_FILE):
        return False
    with open(USER_DATA_FILE, "r") as file:
        for line in file:
            stored_username, _ = line.strip().split(":")
            if stored_username == username:
                return True
    return False

def login_user(username, password):
    if not user_exists(username):
        print("Username does not exist.")
        return False

    with open(USER_DATA_FILE, "r") as file:
        for line in file:
            stored_username, stored_hashed_password = line.strip().split(":")
            if stored_username == username:
                if verify_password(password, stored_hashed_password.encode('utf-8')):
                    print("Login successful.")
                    return True
                else:
                    print("Incorrect password.")
                    return False
    return False

def validate_username(username):
    if not username:
        return (False, "Username cannot be empty.")
    return (True, "")

def validate_password(password):
    if not password:
        return (False, "Password cannot be empty.")

    if len(password) < 8:
        return (False, "Password must be at least 8 characters long.")

    return (True, "")

def display_menu():
    """Displays the main menu options."""
    print("\n" + "="*50)
    print(" MULTI-DOMAIN INTELLIGENCE PLATFORM")
    print(" Secure Authentication System")
    print("="*50)
    print("\n[1] Register a new user")
    print("[2] Login")
    print("[3] Exit")
    print("-"*50)

def main():
    """Main program loop."""
    print("\nWelcome to the Week 7 Authentication System!")
    while True:
        display_menu()
        choice = input("\nPlease select an option (1-3): ").strip()

        if choice == '1':
            # Registration flow
            print("\n--- USER REGISTRATION ---")
            username = input("Enter a username: ").strip()
            # Validate username
            is_valid, error_msg = validate_username(username)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue
            password = input("Enter a password: ").strip()

            # Validate password
            is_valid, error_msg = validate_password(password)
            if not is_valid:
                print(f"Error: {error_msg}")
                continue
            # Confirm password
            password_confirm = input("Confirm password: ").strip()
            if password != password_confirm:
                print("Error: Passwords do not match.")
                continue
            # Register the user
            register_user(username, password)
        elif choice == '2':
            # Login flow
            print("\n--- USER LOGIN ---")
            username = input("Enter your username: ").strip()
            password = input("Enter your password: ").strip()
            # Attempt login
            if login_user(username, password):
                print("\nYou are now logged in.")
                print("(In a real application, you would now access the dashboard")
                # Optional: Ask if they want to logout or exit
                input("\nPress Enter to return to main menu...")
        elif choice == '3':
            # Exit
            print("\nThank you for using the authentication system.")
            print("Exiting...")
            break
        else:
            print("\nError: Invalid option. Please select 1, 2, or 3.")



if __name__ == "__main__":
    main()

