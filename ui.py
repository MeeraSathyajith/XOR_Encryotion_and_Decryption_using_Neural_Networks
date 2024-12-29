import sys
from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QLineEdit, QLabel, QMessageBox
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont
from encryption_model import xor_encrypt_decrypt, generate_key, train_model, decrypt_with_model
import hashlib

# Main Window with Encryption and Decryption options
class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Encryption/Decryption App")
        
        # Set fixed size
        self.setFixedSize(1100, 600)
        
        # Main layout
        layout = QVBoxLayout()
        
        # Title label
        title_label = QLabel("XOR Encryption and Neural Network Decryption")
        title_label.setFont(QFont("Arial", 28))
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Encrypt button
        self.encrypt_button = QPushButton("Encrypt")
        self.encrypt_button.setFont(QFont("Arial", 32))
        self.encrypt_button.setStyleSheet("background-color: #5DADE2; color: white; padding: 10px; border-radius: 5px;")
        self.encrypt_button.clicked.connect(self.show_encrypt_window)
        layout.addWidget(self.encrypt_button)
        
        # Decrypt button
        self.decrypt_button = QPushButton("Decrypt")
        self.decrypt_button.setFont(QFont("Arial", 32))
        self.decrypt_button.setStyleSheet("background-color: #48C9B0; color: white; padding: 10px; border-radius: 5px;")
        self.decrypt_button.clicked.connect(self.show_decrypt_window)
        layout.addWidget(self.decrypt_button)
        
        self.setLayout(layout)

    def show_encrypt_window(self):
        self.encrypt_window = EncryptWindow(self)
        self.encrypt_window.show()
        self.close()

    def show_decrypt_window(self):
        self.decrypt_window = DecryptWindow(self)
        self.decrypt_window.show()
        self.close()

# Encrypt Window with passkey entry
class EncryptWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("Encryption Window")
        
        # Set fixed size
        self.setFixedSize(800, 600)
        
        layout = QVBoxLayout()
        
        # Message input
        self.message_input = QLineEdit(self)
        self.message_input.setPlaceholderText("Enter your message")
        layout.addWidget(QLabel("Message:"))
        layout.addWidget(self.message_input)
        
        # Passkey input
        self.passkey_input = QLineEdit(self)
        self.passkey_input.setPlaceholderText("Enter a passkey for decryption")
        layout.addWidget(QLabel("Passkey:"))
        layout.addWidget(self.passkey_input)
        
        # Encrypt button
        self.encrypt_button = QPushButton("Generate Key and Encrypt")
        self.encrypt_button.setStyleSheet("background-color: #5DADE2; color: white; padding: 10px; border-radius: 5px;")
        self.encrypt_button.clicked.connect(self.encrypt_message)
        layout.addWidget(self.encrypt_button)
        
        # Generated key display
        self.key_label = QLabel("Generated Key:")
        self.key_label.setFont(QFont("Arial", 20))
        layout.addWidget(self.key_label)
        
        # Ciphertext display
        self.ciphertext_label = QLabel("Ciphertext:")
        self.ciphertext_label.setFont(QFont("Arial", 20))
        layout.addWidget(self.ciphertext_label)
        
        # Back button
        self.back_button = QPushButton("Back")
        self.back_button.setStyleSheet("background-color: #E74C3C; color: white; padding: 10px; border-radius: 5px;")
        self.back_button.clicked.connect(self.go_back)
        layout.addWidget(self.back_button)
        
        self.setLayout(layout)

    def encrypt_message(self):
        message = self.message_input.text()
        passkey = self.passkey_input.text()
        
        if message and passkey:
            # Generate key based on passkey
            key = self.generate_key_from_passkey(passkey, len(message))
            ciphertext = xor_encrypt_decrypt(message, key)
            
            # Display key and ciphertext
            self.key_label.setText(f"Generated Key: {key}")
            self.ciphertext_label.setText(f"Ciphertext: {ciphertext}")
            
            # Save key, ciphertext, passkey, and message for decryption
            self.ciphertext = ciphertext
            self.key = key
            self.passkey = passkey
            self.message = message
        else:
            QMessageBox.warning(self, "Input Error", "Please enter both a message and a passkey.")

    def generate_key_from_passkey(self, passkey, length):
        # Hash the passkey using SHA256 to ensure a fixed-length key
        hashed_passkey = hashlib.sha256(passkey.encode('utf-8')).hexdigest()
        # Repeat the hash to match the length of the message
        return (hashed_passkey * ((length // len(hashed_passkey)) + 1))[:length]

    def go_back(self):
        self.main_window.show()
        self.close()

# Decrypt Window with passkey input
class DecryptWindow(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.main_window = main_window
        self.setWindowTitle("Decryption Window")
        
        # Set fixed size
        self.setFixedSize(800, 600)
        
        layout = QVBoxLayout()
        
   # Increase font size of QLineEdit (Passkey input)
        self.key_input = QLineEdit(self)
        self.key_input.setPlaceholderText("Enter passkey to decrypt")
        self.key_input.setStyleSheet("font-size: 16px;")  # Set font size to 16px

        layout.addWidget(QLabel("Passkey:"))
        layout.addWidget(self.key_input)

        # Decrypt button
        self.decrypt_button = QPushButton("Decrypt Message")
        self.decrypt_button.setStyleSheet("background-color: #48C9B0; color: white; padding: 10px; border-radius: 5px;")
        self.decrypt_button.clicked.connect(self.decrypt_message)
        layout.addWidget(self.decrypt_button)
        
        # Decrypted message display
        self.decrypted_label = QLabel("Decrypted Message:")
        self.decrypted_label.setFont(QFont("Arial", 20))
        layout.addWidget(self.decrypted_label)
        
        # Back button
        self.back_button = QPushButton("Back")
        self.back_button.setStyleSheet("background-color: #E74C3C; color: white; padding: 10px; border-radius: 5px;")
        self.back_button.clicked.connect(self.go_back)
        layout.addWidget(self.back_button)
        
        self.setLayout(layout)

    def decrypt_message(self):
        passkey = self.key_input.text()
        
        if hasattr(self.main_window, 'encrypt_window') and passkey:
            # Validate the passkey and decrypt if correct
            if passkey == self.main_window.encrypt_window.passkey:
                model = train_model(
                    self.main_window.encrypt_window.ciphertext,
                    self.main_window.encrypt_window.key,
                    self.main_window.encrypt_window.message
                )
                decrypted_message = decrypt_with_model(
                    model,
                    self.main_window.encrypt_window.ciphertext,
                    self.main_window.encrypt_window.key
                )
                self.decrypted_label.setText(f"Decrypted Message: {decrypted_message}")
            else:
                QMessageBox.warning(self, "Decryption Error", "Invalid passkey.")
        else:
            QMessageBox.warning(self, "Input Error", "Please enter a valid passkey.")

    def go_back(self):
        self.main_window.show()
        self.close()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())


