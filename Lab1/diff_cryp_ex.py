# REFERENCES
# The main reference used for this  is the fantastic tutorial into linear and differential cryptanalysis by Howard Heys available at http://www.engr.mun.ca/~howard/PAPERS/ldc_tutorial.pdf
# Another notable reference is the seminal paper by Biham and Shamir that introduced differential cryptanalysis (available at https://dl.acm.org/doi/10.5555/646755.705229)
# Regarding the graphics, we have been heavily inspired by TikzforCryptographers .
# The title image is from Pexels .
# Source: https://www.schutzwerk.com/blog/differential-cryptanalysis-2/

import random
sbox = [6, 7, 13, 14, 3, 0, 10, 9, 11, 8, 15, 5, 4, 2, 1, 12]

def round_function(input, key):
    return sbox[key ^ input]

def encrypt(input, key0, key1):
    return round_function(input, key0) ^ key1



def get_difference_distribution_table():
    print("[*] Computing difference distribution table.")
    diff_dist_table = [[0 for x in range(16)] for y in range(16)]
    for in_diff in range(16):
        for input0 in range(16):
            input1 = input0 ^ in_diff
            out_diff = sbox[input0] ^ sbox[input1]
            diff_dist_table[in_diff][out_diff] = diff_dist_table[in_diff][out_diff] + 1
    return diff_dist_table


def matrix_pretty_print(matrix):
    s = [[str(e) for e in row] for row in matrix]
    lens = [max(map(len, col)) for col in zip(*s)]
    fmt = '  '.join('{{:{}}}'.format(x) for x in lens)
    table = [fmt.format(*row) for row in s]
    print('\n'.join(table))


diff_dist_table = get_difference_distribution_table()
matrix_pretty_print(diff_dist_table)

print("[*] Choosing differential characteristic 7 -> 13")

def gen_possible_intermediate_values(input_diff, output_diff):
    good_pairs = []
    for input0 in range(16):
        input1 = input0 ^ input_diff
        if sbox[input0] ^ sbox[input1] == output_diff:
            good_pairs.append([input0, input1])
    return good_pairs

intermediate_values = gen_possible_intermediate_values(7, 13)
print("[*] Possible intermediate values: " + str(intermediate_values))

def gen_plain_cipher_pairs(input_diff, num):
    # Generate num plaintext, ciphertext pairs with fixed input difference.
    # Remember, this is a chosen plaintext attack
    # random key which we want to recover
    key = (random.randint(0, 15), random.randint(0, 15))
    print("[*] Real key: %s %s" % (key[0], key[1]))
    pairs = []
    for input0 in random.sample(range(16), num):
        input1 = input0 ^ input_diff
        output0 = encrypt(input0, key[0], key[1])
        output1 = encrypt(input1, key[0], key[1])
        pairs.append(((input0, input1), (output0, output1)))
    return pairs


plain_cipher_pairs = gen_plain_cipher_pairs(7, 3)

def find_good_pair(plain_cipher_pairs, output_diff):
    print("[*] Searching for good pairs.")
    for ((input0, input1), (output0, output1)) in plain_cipher_pairs:
        if output0 ^ output1 == output_diff:
            return ((input0, input1), (output0, output1))
    raise Exception("No good pair found.")

((good_p0, good_p1), (good_c0, good_c1)) = find_good_pair(plain_cipher_pairs, 13)

print("[*] Found a good pair: " + str(((good_p0, good_p1), (good_c0, good_c1))))

def validate_key(guessed_k0, guessed_k1):
    """Checks a key against known plaintext-ciphertext pair and returns True if the key is correct."""
    for ((input0, input1), (output0, output1)) in plain_cipher_pairs:
        if encrypt(input0, guessed_k0, guessed_k1) != output0:
            return False
        if encrypt(input1, guessed_k0, guessed_k1) != output1:
            return False
    return True

def recover_key():
    print("[*] Brute-Forcing remaining key space")
    for (p0, p1) in intermediate_values:
        guessed_k0 = p0 ^ good_p0
        guessed_k1 = sbox[p0] ^ good_c0
        if validate_key(guessed_k0, guessed_k1):
            print("Recovered key --> %s %s" % (guessed_k0, guessed_k1))
        else:
            print("                  %s %s" % (guessed_k0, guessed_k1))


recover_key()

