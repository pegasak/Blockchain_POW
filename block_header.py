import time
from gost_hash import hexdigest, generate_prng
from merkle_tree import build_merkle_root

block_size = b"\x01\x00\x02\x00"

prev_block_hash = generate_prng("Zhukov Alexey && Pegasov Kirill", count=1)[0]

merkle_root = build_merkle_root()

t = time.localtime()
timestamp = bytes([t.tm_hour, t.tm_mday, t.tm_mon, t.tm_year - 2000])

print(" Начинаем подбор nonce...")
max_nonce = 2**32
for nonce in range(max_nonce):
    nonce_bytes = nonce.to_bytes(4, 'big')

    header = block_size + prev_block_hash + merkle_root + timestamp + nonce_bytes
    h = bytes.fromhex(hexdigest(256, header))

    if int.from_bytes(h, 'big') >> 251 == 0:
        print(f" Найден nonce: {nonce}")
        print("Header hash:", h.hex())
        break
else:
    print(" Не удалось найти nonce (что маловероятно)")
