from password_manager import MasterPassword , PasswordManager , Vault , Encryption
import json
from cryptography.fernet import Fernet
import builtins
#=================================================================Test Hash Password=================================================================
def test_hash_password_same_input_same_hash():
    mp = MasterPassword("pass", b"salt")
    h1 = mp.hash_password("abc", b"salt")
    h2 = mp.hash_password("abc", b"salt")

    assert h1 == h2
#=================================================================Test Verify Master Password=================================================================
def test_verify_master_password(tmp_path, monkeypatch):
    fake_file = tmp_path / "master.key"
    password = "Secret123!"
    mp = MasterPassword(password, b"")

    salt = b"abc"
    hash_val = mp.hash_password(password, salt)
    fake_file.write_text(json.dumps({"salt": salt.hex(),"hash": hash_val.hex()}))

    monkeypatch.setattr("password_manager.Master_File", str(fake_file))

    assert mp.verify_master_password(password) is True
#=================================================================Test Key Derivation=================================================================
def test_key_derivation_same_password_same_key():
    e = Encryption("pass", b"salt")

    k1 = e.derive_key("pass", b"salt")
    k2 = e.derive_key("pass", b"salt")

    assert k1 == k2
#=================================================================Test Load and Save=================================================================
def test_save_and_load(tmp_path, monkeypatch):
    key = Fernet.generate_key()
    fernet = Fernet(key)

    fake_vault = tmp_path / "vault.json"
    monkeypatch.setattr("password_manager.Vault_File", str(fake_vault))

    vault_obj = Vault(fernet)

    data = [{"website": "google", "password": "123"}]

    vault_obj.save_vault(data, fernet)
    loaded = vault_obj.load_vault(fernet)

    assert loaded == data
#=================================================================Test Search Passwords=================================================================
def test_search_passwords(monkeypatch, capsys):
    vault = [
        {"id": 1, "website": "google", "username": "me", "password": "123", "notes": ""}
    ]

    monkeypatch.setattr(builtins, "input", lambda _: "google")

    pm = PasswordManager(vault, None)
    pm.search_passwords(vault)

    captured = capsys.readouterr()
    assert "google" in captured.out