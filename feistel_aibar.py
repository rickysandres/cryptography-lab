import random
# S-BOX из шифра Serpent
# Источник: Anderson, Biham, Knudsen, "Serpent: A Proposal for the Advanced Encryption Standard" (1998)
S_BOX = {
    "0000": "0011",  # 0 -> 3
    "0001": "1000",  # 1 -> 8
    "0010": "1111",  # 2 -> F
    "0011": "0001",  # 3 -> 1
    "0100": "1010",  # 4 -> A
    "0101": "0110",  # 5 -> 6
    "0110": "0101",  # 6 -> 5
    "0111": "1011",  # 7 -> B
    "1000": "1110",  # 8 -> E
    "1001": "1101",  # 9 -> D
    "1010": "0100",  # A -> 4
    "1011": "0010",  # B -> 2
    "1100": "0111",  # C -> 7
    "1101": "0000",  # D -> 0
    "1110": "1001",  # E -> 9
    "1111": "1100",  # F -> C
}

BLOCK_SIZE = 64
HALF = 32
NUM_ROUNDS = 16
NIBBLE = 4

#baz oper

def xor_bits(a, b):
    return "".join("0" if a[i] == b[i] else "1" for i in range(len(a)))

def rotl(bits, n):
    n = n % len(bits)
    return bits[n:] + bits[:n]

#key schedule 16 undkeys по 32 bit из ключа >= 128 bit

def generate_subkeys(master_key, num_rounds=NUM_ROUNDS):
    if len(master_key) < 128:
        raise ValueError("Мастер-ключ должен быть не менее 128 бит.")

    L = master_key[:64]
    R = master_key[64:128]

    rest = master_key[128:]
    if rest:
        if len(rest) % 64 != 0:
            rest = rest.ljust((len(rest) // 64 + 1) * 64, "0")
        for i in range(0, len(rest), 64):
            chunk = rest[i:i + 64]
            if (i // 64) % 2 == 0:
                L = xor_bits(L, chunk)
            else:
                R = xor_bits(R, chunk)

    subkeys = []
    for r in range(1, num_rounds + 1):
        L = xor_bits(L, rotl(R, r))
        R = xor_bits(R, rotl(L, r))
        combined = xor_bits(L, R)
        subkey32 = combined[:32]
        round_counter = format(r % (2**32), "032b")
        subkey32 = xor_bits(subkey32, round_counter)
        subkeys.append(subkey32)
    return subkeys

#round f
def f_function(right_half, round_key):
    x = xor_bits(right_half, round_key)
    x = "".join(S_BOX[x[i:i + 4]] for i in range(0, len(x), 4))
    x = x[-3:] + x[:-3]
    return x

#round feistel
def feistel_encrypt_block(block, subkeys, verbose=False):
    L = block[:HALF]
    R = block[HALF:]
    for r, k in enumerate(subkeys):
        if verbose and r == 0:
            print("\n--- РАУНД 1 (подробно) ---")
            print("L:", L)
            print("R:", R)
            print("Подключ:", k)
        f_out = f_function(R, k)
        newL = R
        newR = xor_bits(L, f_out)
        L, R = newL, newR
        if verbose and r == 0:
            print("F(R,K):", f_out)
            print("После раунда L:", L)
            print("После раунда R:", R)
    return R + L   # финальный swap


def feistel_decrypt_block(block, subkeys, verbose=False):
    L = block[:HALF]
    R = block[HALF:]
    for r, k in enumerate(reversed(subkeys)):
        if verbose and r == 0:
            print("\n--- РАУНД 1 расшифрования (подробно) ---")
            print("L:", L)
            print("R:", R)
            print("Подключ:", k)
        f_out = f_function(R, k)
        newL = R
        newR = xor_bits(L, f_out)
        L, R = newL, newR
        if verbose and r == 0:
            print("F(R,K):", f_out)
            print("После раунда L:", L)
            print("После раунда R:", R)
    return R + L   # тот же финальный swap

#паддинг ANSI zX.923 (ниббл)

def pad_message(bits):
    rem_nibble = len(bits) % NIBBLE
    if rem_nibble != 0:
        bits = bits.ljust(len(bits) + (NIBBLE - rem_nibble), "0")

    total_nibbles = len(bits) // NIBBLE
    pad_nibbles = (16 - (total_nibbles % 16)) % 16
    if pad_nibbles == 0:
        pad_nibbles = 16

    zero_nibbles = pad_nibbles - 1
    count_nibble = pad_nibbles % 16   # 16 кодируется как 0
    padded = bits + ("0" * (zero_nibbles * NIBBLE)) + format(count_nibble, "04b")
    return padded


def unpad_message(bits):
    last_nibble = int(bits[-NIBBLE:], 2)
    if last_nibble == 0:
        last_nibble = 16
    if last_nibble > len(bits) // NIBBLE:
        raise ValueError("Некорректный паддинг ANSI X.923.")
    padding_start = len(bits) - last_nibble * NIBBLE
    middle = bits[padding_start:-NIBBLE]
    if any(c != "0" for c in middle):
        raise ValueError("Некорректный паддинг ANSI X.923 (ненулевые нибблы).")
    return bits[:padding_start]

#разбиение на блоки и IV

def split_blocks(bits):
    blocks = []
    for i in range(0, len(bits), BLOCK_SIZE):
        b = bits[i:i + BLOCK_SIZE]
        if len(b) < BLOCK_SIZE:
            b = b.ljust(BLOCK_SIZE, "0")
        blocks.append(b)
    return blocks


def random_iv():
    return "".join(random.choice("01") for _ in range(BLOCK_SIZE))

#ECB

def ecb_encrypt(message, subkeys):
    out = ""
    for i, p in enumerate(split_blocks(message)):
        out += feistel_encrypt_block(p, subkeys, verbose=(i == 0))
    return out


def ecb_decrypt(ciphertext, subkeys):
    out = ""
    for i, c in enumerate(split_blocks(ciphertext)):
        out += feistel_decrypt_block(c, subkeys, verbose=(i == 0))
    return out

#CBC

def cbc_encrypt(message, subkeys, iv):
    blocks = split_blocks(message)
    prev_c = iv
    out = ""
    for i, p in enumerate(blocks):
        x = xor_bits(p, prev_c)
        c = feistel_encrypt_block(x, subkeys, verbose=(i == 0))
        out += c
        prev_c = c
    return out


def cbc_decrypt(ciphertext, subkeys, iv):
    blocks = split_blocks(ciphertext)
    prev_c = iv
    out = ""
    for i, c in enumerate(blocks):
        x = feistel_decrypt_block(c, subkeys, verbose=(i == 0))
        p = xor_bits(x, prev_c)
        out += p
        prev_c = c
    return out

#универсальные обёртки (w паддингом)
def encrypt_message(message, subkeys, mode="ECB", iv=None):
    padded = pad_message(message)
    if mode == "ECB":
        return ecb_encrypt(padded, subkeys), None
    if mode == "CBC":
        if iv is None:
            iv = random_iv()
        return cbc_encrypt(padded, subkeys, iv), iv
    raise ValueError("Неизвестный режим: " + mode)


def decrypt_message(ciphertext, subkeys, mode="ECB", iv=None):
    if mode == "ECB":
        raw = ecb_decrypt(ciphertext, subkeys)
    elif mode == "CBC":
        if iv is None:
            raise ValueError("Для CBC нужен IV.")
        raw = cbc_decrypt(ciphertext, subkeys, iv)
    else:
        raise ValueError("Неизвестный режим: " + mode)
    return unpad_message(raw)
#ввод только бинарных строк
def input_bits(prompt, min_bits, must_be_multiple_of=None):
    while True:
        v = input(prompt).replace(" ", "").replace("\n", "")
        if not v:
            print("Ошибка: пусто.")
            continue
        if any(c not in "01" for c in v):
            print("Ошибка: допускаются только 0 и 1.")
            continue
        if len(v) < min_bits:
            print(f"Ошибка: нужно ≥ {min_bits} бит (сейчас {len(v)}).")
            continue
        if must_be_multiple_of and len(v) % must_be_multiple_of != 0:
            print(f"Ошибка: длина должна быть кратна {must_be_multiple_of} битам.")
            continue
        return v


def choose_mode():
    while True:
        print("\nВыбор режима:")
        print("1) ECB")
        print("2) CBC")
        m = input("Режим (1/2): ").strip()
        if m == "1":
            return "ECB"
        if m == "2":
            return "CBC"
        print("Ошибка: введите 1 или 2.")


def main():
    while True:
        print("Фейстель + Serpent S-Box")
        print("1) Зашифровать")
        print("2) Расшифровать")
        print("3) Выйти")
        choice = input("Выбор: ").strip()

        if choice == "1":
            mode = choose_mode()
            msg = input_bits("Сообщение (бинарная строка, ≥ 256 бит):\n", 256)
            key = input_bits("Ключ (бинарная строка, ≥ 128 бит, кратно 64):\n", 128, 64)
            subkeys = generate_subkeys(key)
            ct, iv = encrypt_message(msg, subkeys, mode=mode)
            print(f"\nРежим: {mode}")
            if iv:
                print("IV (бинарная строка):", iv)
            print("ШИФРОТЕКСТ:", ct)
            n_blocks = len(split_blocks(pad_message(msg)))
            print(f"Блоков: {n_blocks}, раундов на блок: {NUM_ROUNDS}, всего: {n_blocks * NUM_ROUNDS}")

        elif choice == "2":
            mode = choose_mode()
            ct = input_bits("Шифротекст (бинарная строка):\n", 256)
            key = input_bits("Ключ (бинарная строка, ≥ 128 бит, кратно 64):\n", 128, 64)
            subkeys = generate_subkeys(key)
            iv = None
            if mode == "CBC":
                iv = input_bits("IV (бинарная строка, ровно 64 бита):\n", BLOCK_SIZE)
                if len(iv) != BLOCK_SIZE:
                    print("Ошибка: IV должен быть ровно 64 бита.")
                    continue
            pt = decrypt_message(ct, subkeys, mode=mode, iv=iv)
            print(f"\nРежим: {mode}")
            print("РАСШИФРОВАНО:", pt)

        elif choice == "3":
            print("Выход.")
            break
main()
