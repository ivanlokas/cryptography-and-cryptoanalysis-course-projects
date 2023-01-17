#!/usr/bin/env python3

import os

from typing import Any, Dict, Optional, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class MessengerClient:
    """
    Messenger client class

    Attributes:
        MessengerClient.salt (bytes): Salt that will be used
        MessengerClient.message_key_info (bytes): Info that will be used to create message keys
        MessengerClient.chain_key_info (bytes): Info that will be used to create chain keys
        MessengerClient.nonce_length (int): Nonce length
    """

    salt = b'0b00110000001100000011001100110110001101010011000100111000001101100011010000110100'
    message_key_info = b'0b01'
    chain_key_info = b'0b02'
    nonce_length = 12  # NIST recommends a 96-bit nonce length

    # Custom exceptions

    class MessengerClientException(Exception):
        """ Messenger client exception """

    class MaxSkipException(MessengerClientException):
        """ Exception raised when maximum number of messages are skipped """

    @staticmethod
    def _generate_nonce() -> bytes:
        """
        Generate nonce with specified length

        Returns:
            bytes: Nonce with specified length
        """

        return os.urandom(MessengerClient.nonce_length)

    def __init__(self, username: str, max_skip: int = 10) -> None:
        """
        Initializes a client

        Args:
            username (str): Client username
            max_skip (int): Maximum number of message keys that can be skipped in a single chain
        """

        # Client username
        self.username = username

        # Data regarding active connections
        self.conn = dict()

        # Maximum number of message keys that can be skipped in a single chain
        self.max_skip = max_skip

    def add_connection(self, username: str, chain_key_send: bytes, chain_key_recv: bytes) -> None:
        """
        Add a new connection

        Args:
            username (str): User that we want to talk to
            chain_key_send (bytes): Sending chain key (CKs) of the username
            chain_key_recv (bytes): Receiving chain key (CKr) of the username
        """

        self.conn[username] = {
            "chain_key_send": chain_key_send,
            "chain_key_recv": chain_key_recv,
            "num_msg_send": 0,
            "num_msg_recv": 0,
            "skip_keys_dict": dict()
        }

    @staticmethod
    def _generate_message_and_chain_key(chain_key: bytes) -> Tuple[bytes, bytes]:
        """
        Generate message key

        Args:
            chain_key (bytes): Chain key for generating message key

        Returns:
            Tuple[bytes, bytes]: Message and chain key
        """

        message_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=MessengerClient.salt,
            info=MessengerClient.message_key_info,
        ).derive(chain_key)

        chain_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=MessengerClient.salt,
            info=MessengerClient.chain_key_info,
        ).derive(chain_key)

        return message_key, chain_key

    def encrypt_message(self, username: str, message: str) -> Tuple[bytes, Dict[str, Any]]:
        """
        Encrypts a given message

        Args:
            username (str): The receiver of the message
            message (str): Message as string that will be encrypted

        Returns:
            Tuple[bytes, Dict[str, Any]]: Encrypted message (ciphertext) as bytes and header
        """

        # Generate message and chain keys
        message_key, chain_key = MessengerClient._generate_message_and_chain_key(self.conn[username]['chain_key_send'])

        # Update chain key
        self.conn[username]['chain_key_send'] = chain_key

        # Create header
        header = {
            "nonce": MessengerClient._generate_nonce(),
            "num_msg_send": self.conn[username]['num_msg_send']
        }

        # Update number of sent messages
        self.conn[username]['num_msg_send'] += 1

        # Encrypt message
        encrypted_message = AESGCM(message_key).encrypt(
            nonce=header["nonce"],
            data=message.encode(),
            associated_data=str(header).encode()
        )

        return encrypted_message, header

    def decrypt_message(self, username: str, message: bytes, header: Dict[str, Any]) -> str:
        """
        Decrypts a given message

        Args:
            username (str): The sender of the message
            message (bytes): Message as bytes that will be decrypted
            header (Dict[str, Any]): Header

        Returns:
            str: Decrypted message (plaintext) as string

        Raises:
            MessengerClientException: If decryption fails (possible replay attack)
        """

        # Try skipped message keys
        plaintext_message = self.try_skipped_message_keys(username, message, header)

        if plaintext_message is not None:
            return plaintext_message

        # Skip message keys
        self.skip_message_keys(username, header)

        # Generate message and chain keys
        message_key, chain_key = MessengerClient._generate_message_and_chain_key(self.conn[username]['chain_key_recv'])

        # Update chain key
        self.conn[username]['chain_key_recv'] = chain_key

        # Update number of sent messages
        self.conn[username]['num_msg_recv'] += 1

        # Decrypted message
        try:
            decrypted_message = AESGCM(message_key).decrypt(
                nonce=header["nonce"],
                data=message,
                associated_data=str(header).encode()
            ).decode()
        except InvalidTag:
            raise MessengerClient.MessengerClientException()

        return decrypted_message

    def try_skipped_message_keys(self, username: str, message: bytes, header: Dict[str, Any]) -> Optional[str]:
        """
        Tries skipped message keys

        Args:
            username (str): The sender of the message
            message (bytes): Given message as bytes
            header (Dict[str, Any]): Header

        Returns:
            Optional[str]: Skipped message if previously skipped, None otherwise
        """

        if header["num_msg_send"] in self.conn[username]["skip_keys_dict"]:
            message_key = self.conn[username]["skip_keys_dict"][header["num_msg_send"]]
            del self.conn[username]["skip_keys_dict"][header["num_msg_send"]]

            # Decrypted message
            try:
                decrypted_message = AESGCM(message_key).decrypt(
                    nonce=header["nonce"],
                    data=message,
                    associated_data=str(header).encode()
                ).decode()
            except InvalidTag:
                raise MessengerClient.MessengerClientException()

            return decrypted_message

        return None

    def skip_message_keys(self, username: str, header: Dict[str, Any]) -> None:
        """
        Skip message keys

        Args:
            username (str): The sender of the message
            header (Dict[str, Any]): Header

        Raises:
            MaxSkipException: If maximum number of messages are skipped
        """

        until = header["num_msg_send"]

        if self.conn[username]["num_msg_recv"] + self.max_skip < until:
            raise MessengerClient.MaxSkipException()

        if self.conn[username]["chain_key_recv"] is not None:
            while self.conn[username]["num_msg_recv"] < until:
                # Generate message and chain keys
                message_key, chain_key = MessengerClient._generate_message_and_chain_key(
                    self.conn[username]["chain_key_recv"])

                self.conn[username]['chain_key_recv'] = chain_key
                self.conn[username]["skip_keys_dict"][self.conn[username]["num_msg_recv"]] = message_key
                self.conn[username]["num_msg_recv"] += 1

    def send_message(self, username: str, message: str) -> Tuple[bytes, Dict[str, Any]]:
        """
        Send a message to a user

        Get the current sending key of the username, perform a symmetric-ratchet
        step, encrypt the message, update the sending key, return a header and
        a ciphertext.

        Args:
            username (str): User we want to send a message to
            message (str): Plaintext we want to send

        Returns:
             Tuple[bytes, Dict[str, Any]]: Ciphertext and a header
        """

        ciphertext, header = self.encrypt_message(username, message)

        return ciphertext, header

    def receive_message(self, username: str, message_with_header: Tuple[str, Dict[str, Any]]) -> str:
        """
        Receive a message from a user

        Get the username connection data, check if the message is out-of-order,
        perform necessary symmetric-ratchet steps, decrypt the message and
        return the plaintext.

        Args:
            username (str): User who sent the message
            message_with_header (Tuple[str, Dict[str, Any]]): Ciphertext and a header data

        Returns:
            str: Plaintext

        Raises:
            MessengerClientException: If decryption fails (possible replay attack)
        """

        plaintext = self.decrypt_message(username, *message_with_header)

        return plaintext
