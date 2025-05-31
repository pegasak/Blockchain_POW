import os
from gost_hash import hexdigest

def load_signature(sig_path):
    with open(sig_path, "r") as f:
        lines = f.readlines()
    e = int(lines[0].split("=")[1].strip(), 16)
    s = int(lines[1].split("=")[1].strip(), 16)
    return e.to_bytes(64, 'big') + s.to_bytes(64, 'big')

def merkle_hash(data1: bytes, data2: bytes) -> bytes:
    return bytes.fromhex(hexdigest(256, data1 + data2))

def build_merkle_root(tx_dir="transactions", sig_dir="signed") -> bytes:
    leaf_hashes = []
    for i in range(1, 6):  # tx1 ... tx5
        with open(f"{tx_dir}/tx{i}.bin", "rb") as tx_file:
            tx_data = tx_file.read()
        sig_data = load_signature(f"{sig_dir}/tx{i}.sig")
        leaf_input = tx_data + sig_data
        leaf_hash = bytes.fromhex(hexdigest(256, leaf_input))
        leaf_hashes.append(leaf_hash)

    while len(leaf_hashes) > 1:
        if len(leaf_hashes) % 2 != 0:
            leaf_hashes.append(leaf_hashes[-1])
        new_level = []
        for i in range(0, len(leaf_hashes), 2):
            combined = merkle_hash(leaf_hashes[i], leaf_hashes[i + 1])
            new_level.append(combined)
        leaf_hashes = new_level

    return leaf_hashes[0]