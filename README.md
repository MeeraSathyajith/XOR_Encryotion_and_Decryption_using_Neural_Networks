# XOR_Encryotion_and_Decryption_using_Neural_Networks
I developed this software using Python's NN library Pytorch.
XOR Encryption: Encrypt data with a simple XOR algorithm. 
Neural Network Decryption: Train a neural network to figure out and decrypt the XOR-encrypted data.
Whilst encrypting the message you'll be asked to set a passkey, which should be provided inorder to encrypt the message.

This project demonstrates a combination of classical XOR encryption/decryption techniques with a neural network that learns to decrypt XOR-encrypted messages. It is implemented in Python using PyTorch.

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Usage](#usage)
- [How It Works](#how-it-works)
- [File Structure](#file-structure)
- [Future Improvements](#future-improvements)


## Overview
This project:
- Encrypts a message using XOR encryption.
- Trains a feedforward neural network to decrypt the XOR-encrypted message using the encryption key.
- Demonstrates the learning process by showing the loss reduction over epochs.

## Features
- Classical XOR encryption/decryption.
- Random key generation for encryption.
- Neural network implemented with PyTorch to approximate decryption.
- Converts strings to tensors for model compatibility.

## Prerequisites
To run this project, you need:
- Python 3.7 or higher.
- PyTorch 1.10 or higher.

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/xor-nn-decryption.git
   cd xor-nn-decryption
   ```
2. Install dependencies:
   ```bash
   pip install torch
   ```

## Usage
1. Run the script:
   ```bash
   python xor_nn_decryption.py
   ```
2. Enter a message to encrypt when prompted.
3. Observe the encryption, decryption, and neural network training process.
4. After training, view the neural network's predicted decryption.

### Example Output
```
Enter the message you want to encrypt: Hello
Original Message: Hello
Generated Key:    G
Ciphertext:       _S*__
Epoch [500/5000], Loss: 85.2345
...
Decrypted Message (NN Prediction): Hello
```

## How It Works
### XOR Encryption
Each character in the message is XORed with a corresponding character in the key, generating ciphertext. XOR decryption works by XORing the ciphertext with the key.

### Neural Network (DecryptionNN)
- **Architecture**: A feedforward neural network with 2 hidden layers, using ReLU activation.
- **Input**: A concatenated tensor of ciphertext and key.
- **Output**: A tensor representing the decrypted message.
- **Training**: The network is trained to minimize the loss (MSELoss) between the predicted decrypted message and the original message.

## File Structure
```
.
├── xor_nn_decryption.py   # Main script
├── ui.py                  # User Interface
├── README.md              # Project documentation
```

## Future Improvements
- Add support for multi-character keys longer than the message.
- Explore advanced neural network architectures for learning encryption/decryption schemes.
- Integrate a graphical user interface (GUI) for user interaction.

