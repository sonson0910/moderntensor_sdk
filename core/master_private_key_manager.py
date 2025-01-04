import os
from cryptography.fernet import Fernet
from bip_utils import Bip39MnemonicGenerator, Bip39Languages
from pycardano import (
    HDWallet, Address, Network, PaymentVerificationKey, StakeVerificationKey, ExtendedSigningKey
)


class CardanoHDWalletManager:
    def __init__(self, network=Network.TESTNET, encryption_key_path="encryption.key"):
        self.network = network
        self.encryption_key_path = encryption_key_path
        self.cipher_suite = self._initialize_encryption()

    def _initialize_encryption(self):
        """
        Initialize encryption by generating a new encryption key or loading an existing one.
        The encryption key is stored in a specified file and used for secure data storage.
        """
        if os.path.exists(self.encryption_key_path):
            with open(self.encryption_key_path, "rb") as f:
                encryption_key = f.read()
        else:
            encryption_key = Fernet.generate_key()
            with open(self.encryption_key_path, "wb") as f:
                f.write(encryption_key)
        return Fernet(encryption_key)

    def _save_to_file(self, data, path):
        """
        Encrypt and save data to a file.
        :param data: Data to be encrypted and saved.
        :param path: Path to the file where data will be saved.
        """
        encrypted_data = self.cipher_suite.encrypt(data)
        with open(path, "wb") as f:
            f.write(encrypted_data)

    def _load_from_file(self, path):
        """
        Load and decrypt data from a file.
        :param path: Path to the file to be read.
        :return: Decrypted data.
        """
        with open(path, "rb") as f:
            encrypted_data = f.read()
        return self.cipher_suite.decrypt(encrypted_data)

    def save_mnemonic(self, mnemonic, path):
        """
        Encrypt and save a mnemonic to a file.
        :param mnemonic: The mnemonic string to be saved.
        :param path: Path to the file where the mnemonic will be saved.
        """
        self._save_to_file(mnemonic.encode("utf-8"), path)

    def load_mnemonic(self, path):
        """
        Load and decrypt a mnemonic from a file.
        :param path: Path to the file containing the mnemonic.
        :return: Decrypted mnemonic string.
        """
        return self._load_from_file(path).decode("utf-8")

    def save_key(self, key, path):
        """
        Encrypt and save a key to a file.
        :param key: The key object to be saved.
        :param path: Path to the file where the key will be saved.
        """
        self._save_to_file(key.to_primitive(), path)

    def load_key(self, path, key_class):
        """
        Load and decrypt a key from a file.
        :param path: Path to the file containing the encrypted key.
        :param key_class: Class of the key to reconstruct (e.g., ExtendedSigningKey).
        :return: Decrypted key object.
        """
        return key_class.from_primitive(self._load_from_file(path))

    def create_wallet_with_mnemonic(self, mnemonic=None, signing_key_path="me.sk", stake_key_path="me.stake.sk", address_path="me.addr", mnemonic_path="me.mnemonic"):
        """
        Create a new wallet with a provided or generated mnemonic.
        The wallet includes payment and stake keys, and a Shelley address.
        :param mnemonic: Optional mnemonic string. If not provided, a new one is generated.
        :param signing_key_path: Path to save the payment signing key.
        :param stake_key_path: Path to save the stake signing key.
        :param address_path: Path to save the Shelley address.
        :param mnemonic_path: Path to save the encrypted mnemonic.
        :return: Tuple containing mnemonic, keys, and address.
        """
        mnemonic = mnemonic or str(Bip39MnemonicGenerator(lang=Bip39Languages.ENGLISH).FromWordsNumber(24))
        wallet = HDWallet.from_mnemonic(mnemonic)

        payment_wallet = wallet.derive_from_path("m/1852'/1815'/0'/0/0")
        stake_wallet = wallet.derive_from_path("m/1852'/1815'/0'/2/0")

        payment_sk = ExtendedSigningKey.from_hdwallet(payment_wallet)
        stake_sk = ExtendedSigningKey.from_hdwallet(stake_wallet)
        payment_vk = PaymentVerificationKey.from_primitive(payment_wallet.public_key)
        stake_vk = StakeVerificationKey.from_primitive(stake_wallet.public_key)

        address = Address(payment_vk.hash(), stake_vk.hash(), network=self.network)

        self.save_mnemonic(mnemonic, mnemonic_path)
        self.save_key(payment_sk, signing_key_path)
        self.save_key(stake_sk, stake_key_path)
        with open(address_path, "w") as f:
            f.write(str(address))

        return mnemonic, payment_sk, stake_sk, payment_vk, stake_vk, address

    def load_wallet_with_mnemonic(self, signing_key_path="me.sk", stake_key_path="me.stake.sk", address_path="me.addr", mnemonic_path="me.mnemonic"):
        """
        Load an existing wallet from encrypted files.
        :param signing_key_path: Path to the encrypted payment signing key file.
        :param stake_key_path: Path to the encrypted stake signing key file.
        :param address_path: Path to the file containing the Shelley address.
        :param mnemonic_path: Path to the encrypted mnemonic file.
        :return: Tuple containing mnemonic, keys, and address.
        """
        mnemonic = self.load_mnemonic(mnemonic_path)
        wallet = HDWallet.from_mnemonic(mnemonic)

        payment_wallet = wallet.derive_from_path("m/1852'/1815'/0'/0/0")
        stake_wallet = wallet.derive_from_path("m/1852'/1815'/0'/2/0")

        payment_sk = self.load_key(signing_key_path, ExtendedSigningKey)
        stake_sk = self.load_key(stake_key_path, ExtendedSigningKey)
        payment_vk = PaymentVerificationKey.from_primitive(payment_wallet.public_key)
        stake_vk = StakeVerificationKey.from_primitive(stake_wallet.public_key)

        with open(address_path, "r") as f:
            address = Address.from_primitive(f.read().strip())

        return mnemonic, payment_sk, stake_sk, payment_vk, stake_vk, address
