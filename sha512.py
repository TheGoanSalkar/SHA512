import sys
from BitVector import *

class SHA512():
    def __init__(self) -> None:
        pass

    def pad_to_1024n(self, pad_len: int, bv: BitVector) -> BitVector:
        pad_list = [1]
        for _ in range(pad_len - 1):
            pad_list.append(0)
        pad_bv = BitVector(bitlist = pad_list)
        msg_len_bv = BitVector(intVal = len(bv), size = 128)
        bv = bv + pad_bv + msg_len_bv
        return bv

    def sigma(self, idx: int, word: BitVector) -> int:
        if idx == 0:
            n1 = 1
            n2 = 8
            n3 = 7
        elif idx == 1:
            n1 = 19
            n2 = 61
            n3 = 6
        rotr_n1 = word.deep_copy() >> n1
        rotr_n2 = word.deep_copy() >> n2
        shr_n3 = word.deep_copy().shift_right(n3)
        sigma_int = int(rotr_n1 ^ rotr_n2 ^ shr_n3)
        return sigma_int
    
    def calc_ch(self, e: str, f: str, g: str) -> int:
        e = BitVector(hexstring = e)
        f = BitVector(hexstring = f)
        g = BitVector(hexstring = g)
        ch = int((e & f) ^ (~e & g))
        return ch

    def calc_sumE(self, e: str) -> int:
        e = BitVector(hexstring = e)
        rotr_14 = e.deep_copy() >> 14
        rotr_18 = e.deep_copy() >> 18
        rotr_41 = e.deep_copy() >> 41
        sumE = int(rotr_14 ^ rotr_18 ^ rotr_41)
        return sumE
    
    def calc_Maj(self, a: str, b: str, c: str) -> int:
        a = BitVector(hexstring = a)
        b = BitVector(hexstring = b)
        c = BitVector(hexstring = c)
        Maj = int((a & b) ^ (a & c) ^ (b & c))
        return Maj
    
    def calc_sumA(self, a: str) -> int:
        a = BitVector(hexstring = a)
        rotr_14 = a.deep_copy() >> 28
        rotr_18 = a.deep_copy() >> 34
        rotr_41 = a.deep_copy() >> 39
        sumA = int(rotr_14 ^ rotr_18 ^ rotr_41)
        return sumA
    
    def hash(self, in_file: str, hash_file: str) -> None:
        f = open(in_file, "r")
        input = f.readlines()[0]
        f.close()
        bv = BitVector(textstring = input)
        init_hash_buffer = ['6a09e667f3bcc908', 'bb67ae8584caa73b', '3c6ef372fe94f82b', 'a54ff53a5f1d36f1', 
                            '510e527fade682d1', '9b05688c2b3e6c1f', '1f83d9abfb41bd6b', '5be0cd19137e2179']
        K = [
            '428a2f98d728ae22', '7137449123ef65cd', 'b5c0fbcfec4d3b2f', 'e9b5dba58189dbbc',
            '3956c25bf348b538', '59f111f1b605d019', '923f82a4af194f9b', 'ab1c5ed5da6d8118',
            'd807aa98a3030242', '12835b0145706fbe', '243185be4ee4b28c', '550c7dc3d5ffb4e2',
            '72be5d74f27b896f', '80deb1fe3b1696b1', '9bdc06a725c71235', 'c19bf174cf692694',
            'e49b69c19ef14ad2', 'efbe4786384f25e3', '0fc19dc68b8cd5b5', '240ca1cc77ac9c65',
            '2de92c6f592b0275', '4a7484aa6ea6e483', '5cb0a9dcbd41fbd4', '76f988da831153b5',
            '983e5152ee66dfab', 'a831c66d2db43210', 'b00327c898fb213f', 'bf597fc7beef0ee4',
            'c6e00bf33da88fc2', 'd5a79147930aa725', '06ca6351e003826f', '142929670a0e6e70',
            '27b70a8546d22ffc', '2e1b21385c26c926', '4d2c6dfc5ac42aed', '53380d139d95b3df',
            '650a73548baf63de', '766a0abb3c77b2a8', '81c2c92e47edaee6', '92722c851482353b',
            'a2bfe8a14cf10364', 'a81a664bbc423001', 'c24b8b70d0f89791', 'c76c51a30654be30',
            'd192e819d6ef5218', 'd69906245565a910', 'f40e35855771202a', '106aa07032bbd1b8',
            '19a4c116b8d2d0c8', '1e376c085141ab53', '2748774cdf8eeb99', '34b0bcb5e19b48a8',
            '391c0cb3c5c95a63', '4ed8aa4ae3418acb', '5b9cca4f7763e373', '682e6ff3d6b2b8a3',
            '748f82ee5defb2fc', '78a5636f43172f60', '84c87814a1f0ab72', '8cc702081a6439ec',
            '90befffa23631e28', 'a4506cebde82bde9', 'bef9a3f7b2c67915', 'c67178f2e372532b',
            'ca273eceea26619c', 'd186b8c721c0c207', 'eada7dd6cde0eb1e', 'f57d4f7fee6ed178',
            '06f067aa72176fba', '0a637dc5a2c898a6', '113f9804bef90dae', '1b710b35131c471b',
            '28db77f523047d84', '32caab7b40c72493', '3c9ebe0a15c9bebc', '431d67c49c100d4c',
            '4cc5d4becb3e42b6', '597f299cfc657e2a', '5fcb6fab3ad6faec', '6c44198c4a475817'
            ]

        # Step 1: Pad the message
        if len(bv) % 1024 == 0:
            append_len = 1024
            pad_len = append_len - 128            
        else:
            append_len = 1024 - (len(bv) % 1024)
            if append_len > 128:
                pad_len = append_len - 128
            else:
                pad_len = 896 + append_len # 1024 - 128
        bv = self.pad_to_1024n(pad_len = pad_len, bv = bv)

        hash_buffer = []
        for i in range(len(bv) // 1024):
            bitvec = bv[1024*i: 1024*(i + 1)]
            # Step 2: Generate the message schedule
            msg_schedule = []
            for j in range(16):
                word = bitvec[64*j: 64*(j + 1)]
                msg_schedule.append(word)

            for j in range(16, 80):
                word_minus_16 = int(msg_schedule[j - 16].deep_copy())
                word_minus_7 = int(msg_schedule[j - 7].deep_copy())
                sigma_word_minus_15 = self.sigma(idx = 0, word = msg_schedule[j - 15].deep_copy())
                sigma_word_minus_2 = self.sigma(idx = 1, word = msg_schedule[j - 2].deep_copy())
                new_word = (word_minus_16 + sigma_word_minus_15 + word_minus_7 + sigma_word_minus_2) % (pow(2, 64))
                new_word = BitVector(intVal = new_word, size = 64)
                msg_schedule.append(new_word)

            # Step 3: Round-based processing
            for j in range(80):
                if i == 0 and j == 0:
                    hash_buffer = init_hash_buffer
    
                Ch = self.calc_ch(e = hash_buffer[4], f = hash_buffer[5], g = hash_buffer[6])
                sumE = self.calc_sumE(e = hash_buffer[4])
                Maj = self.calc_Maj(a = hash_buffer[0], b = hash_buffer[1], c = hash_buffer[2])
                sumA = self.calc_sumA(a = hash_buffer[0])
                T1 = (int(hash_buffer[7], 16) + Ch + sumE + int(msg_schedule[j]) + int(K[j], 16)) % (pow(2, 64))
                T2 = (sumA + Maj) % (pow(2, 64))

                e = (int(hash_buffer[3], 16) + T1) % (pow(2, 64))
                d = int(hash_buffer[2], 16)
                c = int(hash_buffer[1], 16)
                b = int(hash_buffer[0], 16)
                a = (T1 + T2) % (pow(2, 64))
                h = int(hash_buffer[6], 16)
                g = int(hash_buffer[5], 16)
                f = int(hash_buffer[4], 16)

                hash_buffer = [a, b, c, d, e, f, g, h]
                hash_buffer = [BitVector(intVal = num, size = 64).get_bitvector_in_hex() for num in hash_buffer]

            # Addition of Hash Buffer to Initialization Vector
            init_hash_buffer_int = [int(hexStr, 16) for hexStr in init_hash_buffer]
            hash_buffer = [int(hexStr, 16) for hexStr in hash_buffer]
            hash_buffer = [(num1 + num2) % (pow(2, 64)) for num1, num2 in zip(hash_buffer, init_hash_buffer_int)]
            hash_buffer = [BitVector(intVal = num, size = 64).get_bitvector_in_hex() for num in hash_buffer]
            init_hash_buffer = hash_buffer
                    
        final = ""
        for hexStr in hash_buffer:
            final = final + hexStr
        
        fout = open(hash_file, "w")
        fout.write(final)
        fout.close()
        
if __name__ == "__main__":
    hasher = SHA512()
    hasher.hash(in_file = sys.argv[1], hash_file = sys.argv[2])