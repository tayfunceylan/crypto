import des_tables


def main():
    x = "0111010001100001011110010110011001100011011001010111100101101100"  # x
    k = "0111010001100001011110010110011001100011011001010111100101101100"
    print('plain text:')
    pprint(x)
    y = des_encrypt(x, k)  # y
    print('cipher text:')
    pprint(y)
    new_x = des_decrypt(y, k)  # decrypt(y) = x
    print('decrypting cipher text again:')
    pprint(new_x)
    print(f'encrypting x and then decrypting worked: {x == new_x}')


def des_encrypt(x, k):
    keys = key_gen(k)
    y = des(x, keys, "encrypt")
    return y


def des_decrypt(x, k):
    keys = key_gen(k)
    keys.reverse()
    x = des(x, keys, "decrypt")
    return x


def des(x, keys, mode):
    after_init_perm = permutation(x, des_tables.ip)
    # print("After initial permutation:\n%s" % after_init_perm)

    L, R = [], []
    L.append(after_init_perm[0:32])  # first L
    R.append(after_init_perm[32:64])  # first R
    for runde in range(0, 16):
        L, R = round(runde, L, R, keys)
    y = permutation(R[-1] + L[-1], des_tables.ip_inv)  # ausgangspermutation
    return y


def key_gen(k):  # generates key
    key = []
    after_pc1 = permutation(k, des_tables.pc_1)
    C, D = [], []
    C.append(after_pc1[0:28])  # C0
    D.append(after_pc1[28:56])  # R0
    for i in range(0, 16):
        C.append(leftshift(C[i], i))  # leftshift
        D.append(leftshift(D[i], i))  # leftshift
    for i in range(1, 17):  # Runden 1-16 ohne 0
        key.append(permutation(C[i] + D[i], des_tables.pc_2))  # C und D zusammenführen und permutieren
    return key


def leftshift(input, i):
    if i + 1 in [1, 2, 9, 16]:
        offset = 1  # ein bit verschieben
    else:
        offset = 2
    output = input[offset:] + input[:offset]
    return output


def round(count, L, R, key):
    L.append(R[count])  # next L
    fbox = f_box(R[count], key[count])
    next_R = int(L[count], 2) ^ int(fbox, 2)  # calculates R[count+1]
    R.append(mask(next_R, 32))  # next R
    return L, R


def f_box(r, key):
    expansion = permutation(r, des_tables.e)  # expansion
    xor = int(expansion, 2) ^ int(key, 2)  # xor with key
    xor = mask(xor, 48)
    s = ""
    for i in range(0, 8):  # s-box 1 bis s-box 8
        s += s_box(i, xor[0 + i * 6: 6 + i * 6])
    output = permutation(s, des_tables.func_perm)  # Permutation innerhalb der Funktion
    return output


def s_box(box, input):
    line = int(input[0] + input[-1], 2)
    row = int(input[1:5], 2)
    output = des_tables.S[box][line][row]
    output = mask(output, 6)
    return output


def mask(binary, length):  # returns binary as a 32-bit string
    mask = ""
    for i in range(0, length):
        mask += "0"
    binary_string = bin(binary)[2:]
    return mask[len(binary_string):] + binary_string


def permutation(binary, order):  # permutation
    new = ""
    for i in order:
        # print(i)
        new += binary[i - 1]
    return new


def lr(input):  # splits 64 bit into two 32 bits
    return [input[0:32], input[32:64]]


def pprint(input):  # seperate every fourth bit
    new = ""
    for i in range(0, len(input) // 4 + 1):
        new += input[0 + i * 4:4 + i * 4] + " "
    print(new)


if __name__ == '__main__':
    main()
