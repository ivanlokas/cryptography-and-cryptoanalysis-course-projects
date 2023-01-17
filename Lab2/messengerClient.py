#!/usr/bin/env python3

import os
import pickle

from typing import Dict, Union, Tuple, Any, Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class MessengerClient:
    """
    Messenger client class

    Attributes:
        MessengerClient.salt (bytes): Salt that will be used
        MessengerClient.message_key_info (bytes): Info that will be used to create message keys
        MessengerClient.chain_key_info (bytes): Info that will be used to create chain keys
        MessengerClient.root_key_info (bytes): Info that will be used to create root keys
        MessengerClient.root_chain_key_info (bytes): Info that will be used to create root chain keys
        MessengerClient.nonce_length (int): Nonce length
    """

    salt = b'0b00110000001100000011001100110110001101010011000100111000001101100011010000110100'

    message_key_info = b'0b01'
    chain_key_info = b'0b02'

    root_key_info = b'0b03'
    root_chain_key_info = b'0b04'

    nonce_length = 12  # NIST recommends a 96-bit nonce length

    # Custom exceptions

    class MessengerClientException(Exception):
        """ Messenger client exception """

    class MaxSkipException(MessengerClientException):
        """ Exception raised when maximum number of messages are skipped """

    def __init__(self, username: str, ca_pub_key: EllipticCurvePublicKey) -> None:
        """
        Initializes a client

        Args:
            username (str): Client username
            ca_pub_key (EllipticCurvePublicKey): CA public key
        """

        # Client username
        self.username = username

        # CA public key
        self.ca_pub_key = ca_pub_key

        # Maximum number of message keys that can be skipped in a single chain
        self.max_skip = 10

        # Data regarding active connections
        self.conn = dict()

        # Initial Diffie-Hellman key par
        self.dh_key_pair = None

    @staticmethod
    def _generate_nonce() -> bytes:
        """
        Generate nonce with specified length

        Returns:
            bytes: Nonce with specified length
        """

        return os.urandom(MessengerClient.nonce_length)

    @staticmethod
    def _VERIFY_SIGNATURE(ca_pub_key: EllipticCurvePublicKey, data: bytes, signature) -> None:
        """
        Verify signature

        Args:
            ca_pub_key (EllipticCurvePublicKey): CA public key
            data (bytes): Data
            signature (TODO): Signature that will be verified
        """

        ca_pub_key.verify(
            signature=signature,
            data=data,
            signature_algorithm=ec.ECDSA(hashes.SHA256())
        )

    # Signal external functions

    @staticmethod
    def _GENERATE_DH() -> X25519PrivateKey:
        """
        Returns a new Diffie-Hellman key pair

        Returns:
            X25519PrivateKey: Diffie-Hellman key pair
        """

        return X25519PrivateKey.generate()

    @staticmethod
    def _DH(dh_key_pair: X25519PrivateKey, dh_key_pub: X25519PublicKey):
        """
        Returns the output from the Diffie-Hellman calculation

        Args:
            dh_key_pair (X25519PrivateKey): Diffie-Hellman private key
            dh_key_pub (X25519PublicKey): Diffie-Hellman public key

        Returns:
            : Output from the Diffie-Hellman calculation
        """

        return dh_key_pair.exchange(dh_key_pub)

    @staticmethod
    def _KDF_RK(root_key: bytes, dh_output: bytes) -> Tuple[bytes, bytes]:
        """
        Generate message and root key

        Args:
            root_key (bytes): Root key for generating message key
            dh_output (bytes): Diffie-Hellman output

        Returns:
            Tuple[bytes, bytes]: Root and chain key
        """

        root_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=root_key,
            info=MessengerClient.root_key_info,
        ).derive(dh_output)

        chain_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=root_key,
            info=MessengerClient.root_chain_key_info,
        ).derive(dh_output)

        return root_key, chain_key

    @staticmethod
    def _KDF_CK(chain_key: bytes) -> Tuple[bytes, bytes]:
        """
        Generate message and chain key

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

    def generate_certificate(self) -> Dict[str, Union[X25519PrivateKey, str]]:
        """
        Generates a Diffie-Hellman key pair and returns certificate which contains public key & client username

        Returns:
            Dict[str, Union[X25519PrivateKey, str]]
        """

        # Generate Diffie-Hellman key pair
        self.dh_key_pair = MessengerClient._GENERATE_DH()

        # Serialize public key
        serialized_public_key = self.dh_key_pair.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        # Generate certificate
        certificate = {
            "public_key": serialized_public_key,
            "username": self.username
        }

        return certificate

    def receive_certificate(self, certificate: Dict[str, Union[bytes, str]], signature: bytes) -> None:
        """
        Verifies client certificate

        Args:
            certificate (Dict[str, Union[bytes, str]]): Client certificate
            signature (bytes): Certificate signature
        """

        # Verify signature
        MessengerClient._VERIFY_SIGNATURE(
            ca_pub_key=self.ca_pub_key,
            data=pickle.dumps(certificate),
            signature=signature
        )

        # Create Diffie-Hellman send & receive keys
        dh_key_send = self.dh_key_pair
        dh_key_recv = X25519PublicKey.from_public_bytes(certificate["public_key"])

        # Create shared secret
        shared_secret = MessengerClient._DH(dh_key_send, dh_key_recv)

        # Generate connection
        connection = {
            "dh_key_send": dh_key_send,
            "dh_key_recv": dh_key_recv,
            "shared_secret": shared_secret,
            "root_key": None,
            "chain_key_send": None,
            "chain_key_recv": None,
            "num_msg_send": 0,
            "num_msg_recv": 0,
            "prev_chain_num_msg": 0,
            "skip_keys_dict": dict(),
            "initialized": False
        }

        # Assign connection
        self.conn[certificate["username"]] = connection

    def _update_connection(self, username: str, init_subject: str):
        """
        Generates a connection

        Args:
            username (str): Username that will be used to update the connection
            init_subject (str): Subject of connection ["sender", "receiver"]
        """

        if init_subject.lower() == "sender":
            if not self.conn[username]["initialized"]:
                dh_key_send = MessengerClient._GENERATE_DH()

                # Generate root and chain key
                root_key, chain_key = MessengerClient._KDF_RK(
                    root_key=self.conn[username]["shared_secret"],
                    dh_output=MessengerClient._DH(dh_key_send, self.conn[username]["dh_key_recv"])
                )

                # Update connection
                self.conn[username]["dh_key_send"] = dh_key_send
                self.conn[username]["root_key"] = root_key
                self.conn[username]["chain_key_send"] = chain_key
                self.conn[username]["initialized"] = True

        elif init_subject.lower() == "receiver":
            if not self.conn[username]["initialized"]:
                # Update connection
                self.conn[username]["dh_key_recv"] = None
                self.conn[username]["root_key"] = self.conn[username]["shared_secret"]
                # self.conn[username]["chain_key_send"] = self.conn[username]["shared_secret"]
                self.conn[username]["initialized"] = True

        else:
            raise MessengerClient.MessengerClientException(f"Invalid 'init_subject' ({init_subject}).")

    def send_message(self, username: str, message: str) -> Tuple[bytes, Dict[str, Any]]:
        """
        Send a message to a user

        Args:
            username (str): User we want to send a message to
            message (str): Plaintext we want to send

        Returns:
            Tuple[bytes, Dict[str, Any]]: Ciphertext and a header
        """

        self._update_connection(
            username=username,
            init_subject="sender"
        )

        # Generate message and chain keys
        message_key, chain_key = MessengerClient._KDF_CK(self.conn[username]["chain_key_send"])

        # Update chain key
        self.conn[username]["chain_key_send"] = chain_key

        # Create header
        header = {
            "nonce": MessengerClient._generate_nonce(),
            "dh_key_send": self.conn[username]["dh_key_send"].public_key(),
            "prev_chain_num_msg": self.conn[username]["prev_chain_num_msg"],
            "num_msg_send": self.conn[username]["num_msg_send"]
        }

        # Update number of sent messages
        self.conn[username]["num_msg_send"] += 1

        # Encrypt message
        encrypted_message = AESGCM(message_key).encrypt(
            nonce=header["nonce"],
            data=message.encode(),
            associated_data=str(header).encode()
        )

        return encrypted_message, header

    def receive_message(self, username: str, message_with_header: Tuple[str, Dict[str, Any]]) -> str:
        """
        Receive a message from a user

        Args:
            username (str): User who sent the message
            message_with_header (Tuple[str, Dict[str, Any]]): Ciphertext and a header data

        Returns:
            str: Plaintext

        Raises:
            MessengerClientException: If decryption fails (possible replay attack)
        """

        self._update_connection(
            username=username,
            init_subject="receiver"
        )

        # Unpack message object
        message, header = message_with_header

        # Try skipped message keys
        plaintext_message = self.try_skipped_message_keys(username, message, header)

        if plaintext_message is not None:
            return plaintext_message

        header_dh_key_send = None if header["dh_key_send"] is None else header["dh_key_send"].public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        conn_dh_key_send = None if self.conn[username]["dh_key_recv"] is None else self.conn[username][
            "dh_key_recv"].public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        if header_dh_key_send != conn_dh_key_send:
            # Skip message keys
            self.skip_message_keys(username, header)

            # DH Ratchet
            self.conn[username]["prev_chain_msg_num"] = self.conn[username]["num_msg_send"]
            self.conn[username]["num_msg_send"] = 0
            self.conn[username]["num_msg_recv"] = 0
            self.conn[username]["dh_key_recv"] = header["dh_key_send"]

            dh_output = MessengerClient._DH(self.conn[username]["dh_key_send"], self.conn[username]["dh_key_recv"])

            root_key, chain_key = MessengerClient._KDF_RK(
                root_key=self.conn[username]["root_key"],
                dh_output=dh_output
            )

            self.conn[username]["root_key"] = root_key
            self.conn[username]["chain_key_recv"] = chain_key

            self.conn[username]["dh_key_send"] = MessengerClient._GENERATE_DH()

            dh_output = MessengerClient._DH(self.conn[username]["dh_key_send"], self.conn[username]["dh_key_recv"])

            root_key, chain_key = MessengerClient._KDF_RK(
                root_key=self.conn[username]["root_key"],
                dh_output=dh_output
            )

            self.conn[username]["root_key"] = root_key
            self.conn[username]["chain_key_send"] = chain_key

        # Skip message keys
        self.skip_message_keys(username, header)

        # Generate message and chain keys
        message_key, chain_key = MessengerClient._KDF_CK(self.conn[username]["chain_key_recv"])

        # Update chain key
        self.conn[username]["chain_key_recv"] = chain_key

        # Update number of sent messages
        self.conn[username]["num_msg_recv"] += 1

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
                message_key, chain_key = MessengerClient._KDF_CK(
                    self.conn[username]["chain_key_recv"]
                )

                self.conn[username]['chain_key_recv'] = chain_key
                self.conn[username]["skip_keys_dict"][self.conn[username]["num_msg_recv"]] = message_key
                self.conn[username]["num_msg_recv"] += 1


def main():
    pass


if __name__ == "__main__":
    main()
