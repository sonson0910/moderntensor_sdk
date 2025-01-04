from core.master_private_key_manager import CardanoHDWalletManager

def test_create_wallet_with_mnemonic():
    """
    Test creating a new wallet with a provided or generated mnemonic.
    """
    wallet_manager = CardanoHDWalletManager()

    # Test with generated mnemonic
    mnemonic, payment_sk, stake_sk, payment_vk, stake_vk, addr = wallet_manager.create_wallet_with_mnemonic(
        signing_key_path="test_me.sk",
        stake_key_path="test_me.stake.sk",
        address_path="test_me.addr",
        mnemonic_path="test_me.mnemonic",
    )

    print("=== Test Create Wallet with Generated Mnemonic ===")
    print(f"Mnemonic: {mnemonic}")
    print(f"Payment Signing Key: {payment_sk}")
    print(f"Stake Signing Key: {stake_sk}")
    print(f"Payment Verification Key: {payment_vk}")
    print(f"Stake Verification Key: {stake_vk}")
    print(f"Shelley Address: {addr}")

    # Test with provided mnemonic
    provided_mnemonic = mnemonic  # Reuse the generated mnemonic for testing
    mnemonic, payment_sk, stake_sk, payment_vk, stake_vk, addr = wallet_manager.create_wallet_with_mnemonic(
        mnemonic=provided_mnemonic,
        signing_key_path="test_provided_me.sk",
        stake_key_path="test_provided_me.stake.sk",
        address_path="test_provided_me.addr",
        mnemonic_path="test_provided_me.mnemonic",
    )

    print("\n=== Test Create Wallet with Provided Mnemonic ===")
    print(f"Mnemonic: {mnemonic}")
    print(f"Payment Signing Key: {payment_sk}")
    print(f"Stake Signing Key: {stake_sk}")
    print(f"Payment Verification Key: {payment_vk}")
    print(f"Stake Verification Key: {stake_vk}")
    print(f"Shelley Address: {addr}")


def test_load_wallet_with_mnemonic():
    """
    Test loading an existing wallet with mnemonic.
    """
    wallet_manager = CardanoHDWalletManager()

    # Load wallet
    mnemonic, payment_sk, stake_sk, payment_vk, stake_vk, addr = wallet_manager.load_wallet_with_mnemonic(
        signing_key_path="test_me.sk",
        stake_key_path="test_me.stake.sk",
        address_path="test_me.addr",
        mnemonic_path="test_me.mnemonic",
    )

    print("\n=== Test Load Wallet ===")
    print(f"Mnemonic: {mnemonic}")
    print(f"Payment Signing Key: {payment_sk}")
    print(f"Stake Signing Key: {stake_sk}")
    print(f"Payment Verification Key: {payment_vk}")
    print(f"Stake Verification Key: {stake_vk}")
    print(f"Shelley Address: {addr}")


if __name__ == "__main__":
    test_create_wallet_with_mnemonic()
    test_load_wallet_with_mnemonic()
