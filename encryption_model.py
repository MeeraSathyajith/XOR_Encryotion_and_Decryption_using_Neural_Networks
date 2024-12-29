import torch
import hashlib
import torch.nn as nn
import torch.optim as optim
from random import randint


# XOR encryption and decryption function
def xor_encrypt_decrypt(message, key):
    """XOR encryption/decryption with the key."""
    return ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(message, key))


def generate_key(length):
    """Generate a random key of given length."""
    return ''.join(chr(randint(0, 255)) for _ in range(length))


def generate_key_from_passkey(passkey, length):
    """Generate a key from the passkey using SHA256."""
    hashed_passkey = hashlib.sha256(passkey.encode('utf-8')).hexdigest()
    return (hashed_passkey * ((length // len(hashed_passkey)) + 1))[:length]


# Convert string to tensor
def string_to_tensor(s):
    return torch.tensor([ord(c) for c in s], dtype=torch.float32)


# Convert tensor back to string
def tensor_to_string(t):
    return ''.join(chr(int(c.item())) for c in t)


class DecryptionNN(nn.Module):
    def __init__(self, input_size, hidden_size, output_size):
        super(DecryptionNN, self).__init__()
        # Define layers for the neural network
        self.fc1 = nn.Linear(input_size, hidden_size)
        self.fc2 = nn.Linear(hidden_size, hidden_size)
        self.fc3 = nn.Linear(hidden_size, output_size)

    def forward(self, x):
        x = torch.relu(self.fc1(x))
        x = torch.relu(self.fc2(x))
        x = self.fc3(x)
        return x


























def train_model(ciphertext, key, message, num_epochs=3000, hidden_size=64):
    """Train the neural network to decrypt the message based on ciphertext and passkey."""
    input_size = len(ciphertext) * 2  # Concatenated ciphertext + key
    output_size = len(message)

    model = DecryptionNN(input_size, hidden_size, output_size)
    criterion = nn.MSELoss()  # Using Mean Squared Error loss
    optimizer = optim.Adam(model.parameters(), lr=0.001)

    # Convert ciphertext and key to tensors and concatenate them
    input_tensor = torch.cat((string_to_tensor(ciphertext), string_to_tensor(key)))
    target_tensor = string_to_tensor(message)

    for epoch in range(num_epochs):
        # Forward pass
        output = model(input_tensor)
        loss = criterion(output, target_tensor)

        # Backward pass and optimization
        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        if (epoch + 1) % 500 == 0:
            print(f'Epoch [{epoch+1}/{num_epochs}], Loss: {loss.item():.4f}')

    return model


def decrypt_with_model(model, ciphertext, key):
    """Decrypt the message using the trained model."""
    input_tensor = torch.cat((string_to_tensor(ciphertext), string_to_tensor(key)))

    with torch.no_grad():  # No gradient calculation needed for testing
        decrypted_tensor = model(input_tensor)
        decrypted_message = tensor_to_string(decrypted_tensor)
    
    return decrypted_message


# Example Usage:
if __name__ == "__main__":
    # Define a message to encrypt
    message = input("Enter the message you want to encrypt: ")
    print("Original Message:", message)

    # Generate a passkey and encryption key
    passkey = input("Enter the passkey: ")
    key = generate_key_from_passkey(passkey, len(message))
    print("Generated Key:", key)

    # Encrypt the message
    ciphertext = xor_encrypt_decrypt(message, key)
    print("Ciphertext:", ciphertext)

    Password=input("Enter the passkey to decrypt:")
    if Password==passkey:
    # Train the model
        model = train_model(ciphertext, key, message)
    # Decrypt the message using the model
        decrypted_message = decrypt_with_model(model, ciphertext, key)
        print("Decrypted Message (NN Prediction):", decrypted_message)
    else:
        print("U've entered the wrong passkey.")
