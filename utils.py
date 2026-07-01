"""
SecureVault - Command Line Interface
------------------------------------
Interactive CLI menu for SecureVault features:
1. Analyze Password
2. Generate Password
3. Add Credential
4. Search Credential
5. Update Credential
6. Delete Credential
7. List Credentials
8. Check Password Breach
9. Export Data
0. Exit
"""

import sys
from password_strength_analyzer import check_strength
from password_generator import generate_password
from password_manager import (
    add_credential,
    search_credential,
    update_credential,
    delete_credential,
    list_credentials,
)
from breach_checker import check_breach
from exporter import export_json, export_csv
from logger_config import setup_logger


logger = setup_logger()


def menu() -> None:
    """Display interactive menu."""
    while True:
        print("\n=== SecureVault – Password Security Suite ===")
        print("1. Analyze Password")
        print("2. Generate Password")
        print("3. Add Credential")
        print("4. Search Credential")
        print("5. Update Credential")
        print("6. Delete Credential")
        print("7. List Credentials")
        print("8. Check Password Breach")
        print("9. Export Data")
        print("0. Exit")

        choice = input("Enter choice: ").strip()

        try:
            if choice == "1":
                password = input("Enter password: ")
                result = check_strength(password)
                print(f"Strength: {result['classification']} ({result['score']}/100)")
                if result["suggestions"]:
                    print("Suggestions:", ", ".join(result["suggestions"]))
                logger.info(f"Analyzed password: {password}")

            elif choice == "2":
                length = int(input("Enter length (min 8): "))
                use_upper = input("Include uppercase? (y/n): ").lower() == "y"
                use_lower = input("Include lowercase? (y/n): ").lower() == "y"
                use_digits = input("Include digits? (y/n): ").lower() == "y"
                use_symbols = input("Include symbols? (y/n): ").lower() == "y"
                result = generate_password(length, use_upper, use_lower, use_digits, use_symbols)
                print("Generated Password:", result["password"])
                logger.info("Generated new password")

            elif choice == "3":
                website = input("Website: ")
                username = input("Username: ")
                password = input("Password: ")
                add_credential(website, username, password)
                print("Credential added successfully.")
                logger.info(f"Added credential for {website}")

            elif choice == "4":
                website = input("Enter website to search: ")
                result = search_credential(website)
                if result:
                    print(result)
                else:
                    print("Credential not found.")
                logger.info(f"Searched credential for {website}")

            elif choice == "5":
                website = input("Website: ")
                username = input("Username: ")
                new_password = input("New Password: ")
                if update_credential(website, username, new_password):
                    print("Credential updated successfully.")
                else:
                    print("Credential not found.")
                logger.info(f"Updated credential for {website}")

            elif choice == "6":
                website = input("Website: ")
                username = input("Username: ")
                if delete_credential(website, username):
                    print("Credential deleted successfully.")
                else:
                    print("Credential not found.")
                logger.info(f"Deleted credential for {website}")

            elif choice == "7":
                credentials = list_credentials()
                for entry in credentials:
                    print(entry)
                logger.info("Listed all credentials")

            elif choice == "8":
                password = input("Enter password: ")
                result = check_breach(password)
                print(f"Breaches: {result['breaches']}")
                print(f"Recommendation: {result['recommendation']}")
                logger.info("Checked password breach")

            elif choice == "9":
                json_file = export_json()
                csv_file = export_csv()
                print(f"Exported JSON: {json_file}")
                print(f"Exported CSV: {csv_file}")
                logger.info("Exported vault data")

            elif choice == "0":
                print("Exiting SecureVault. Goodbye!")
                logger.info("Application exited")
                sys.exit()

            else:
                print("Invalid choice. Please try again.")
                logger.warning("Invalid menu choice entered")

        except Exception as e:
            print(f"Error: {e}")
            logger.error(f"Exception occurred: {e}")
