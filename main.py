import os
from schnorr_signature import sign_message, verify_signature, p, q, a
from gost_hash import hexdigest, generate_prng

YOUR_NAME = "Pegasov Kirill"
SEED = "Zhukov Alexey && Pegasov Kirill"
TX_COUNT = 5
TX_SIZE = 200

os.makedirs("transactions", exist_ok=True)
os.makedirs("signed", exist_ok=True)

prng_data = generate_prng(SEED, count=10)
x = int.from_bytes(prng_data[0], 'big') % q
y = pow(a, x, p)

for i in range(TX_COUNT):
    if i == 2:
        tx_data = bytearray(YOUR_NAME.encode("utf-8"))
        tx_data += os.urandom(TX_SIZE - len(tx_data))
    else:
        tx_data = os.urandom(TX_SIZE)

    with open(f"transactions/tx{i+1}.bin", "wb") as f:
        f.write(tx_data)

    k = int.from_bytes(prng_data[i+1], 'big') % q

    e, s = sign_message(tx_data, x, k, a, p, q)

    with open(f"signed/tx{i+1}.sig", "w") as sigf:
        sigf.write(f"e = {hex(e)}\n")
        sigf.write(f"s = {hex(s)}\n")
        sigf.write(f"y = {hex(y)}\n")
