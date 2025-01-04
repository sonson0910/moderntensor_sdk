import os
import sys
import hashlib
from bip_utils import Bip39MnemonicGenerator, Bip39SeedGenerator, Bip39MnemonicValidator, Bip39Languages
from pycardano import HDWallet, Address, Network, PaymentSigningKey, PaymentVerificationKey, StakeVerificationKey, ExtendedSigningKey

def validate_mnemonic(mnemonic):
    """
    Validate a mnemonic to ensure it's well-formed and matches the language.
    :param mnemonic: The mnemonic to validate.
    :return: True if valid, raises ValueError if invalid.
    """
    validator = Bip39MnemonicValidator(Bip39Languages.ENGLISH)
    if not validator.Validate(mnemonic):
        raise ValueError("Invalid mnemonic!")
    return True

print(validate_mnemonic('stay cricket black middle hunt install rival camp remind resist visual angle electric bid quiz brand day target quantum loyal ski dune hand puzzle'))