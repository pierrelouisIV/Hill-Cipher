# -*- coding: utf-8 -*-
# _authors_: Petrus
# _date_ : 12/06/2023
import string
import argparse

import numpy as np
from sympy import Matrix

#
Banner = r"""
     __    __   __   __       __           ______  __  .______    __    __   _______ .______      
    |  |  |  | |  | |  |     |  |         /      ||  | |   _  \  |  |  |  | |   ____||   _  \     
    |  |__|  | |  | |  |     |  |        |  ,----'|  | |  |_)  | |  |__|  | |  |__   |  |_)  |    
    |   __   | |  | |  |     |  |        |  |     |  | |   ___/  |   __   | |   __|  |      /     
    |  |  |  | |  | |  `----.|  `----.   |  `----.|  | |  |      |  |  |  | |  |____ |  |\  \----.
    |__|  |__| |__| |_______||_______|    \______||__| | _|      |__|  |__| |_______|| _| `._____|
                        
    """                                                                                 

#
def parse_args():
	parser = argparse.ArgumentParser(add_help=True, description='This tool is an implementation of the Hill Cipher and automates a plaintext attack')
	parser.add_argument("-t","--text",dest="text",type=str,required=True, help="plaintext or ciphertext")
	parser.add_argument("-m","--mode",dest="mode",type=str, choices=['enc', 'dec', 'attack'], required=True, default='enc', help="encryption/decryption mode or plaintext attack")
	parser.add_argument("-d","--dictionary",dest="dico",type=str,required=True, help="Dictionary")
	parser.add_argument("-k","--key",dest="key",type=str, help="Encryption and decryption key")
	parser.add_argument("-p","--key_length",dest="p", type=int, default=False, help="The key length (dim of the key matrix)")
	parser.add_argument("-c","--crib",dest="crib",type=str, default=False, help="crib to make the plaintext attack")
	return parser.parse_args()



#
Alphabet_mod26 = {
    'A': 0, 'B': 1, 'C': 2, 'D': 3, 'E': 4, 'F': 5, 'G': 6, 'H': 7, 'I': 8, 'J': 9,
    'K': 10, 'L': 11, 'M': 12, 'N': 13, 'O': 14, 'P': 15, 'Q': 16, 'R': 17, 'S': 18, 'T': 19, 'U': 20, 'V': 21,
    'W': 22, 'X': 23, 'Y': 24, 'Z': 25
}



# ------------------------------------- functions -----------------------------------------#

def get_keys_from_value(d, val):
    """Returns the key from the value in the dictionary"""
    for k, v in d.items():
        if v == val:
            return k
    print("Error: this value ",val," doesn't exist in the dictionary")
    




def encrypt(message, clef, N=26, alphabet=Alphabet_mod26, upper=True):
    """Returns the ciphertext from the message, the key which is a matrix n*n 
        and an dictionary which maps character to value"""
    if type(message) is str and type(clef) is list:
        CLEF_ = np.array(clef)
        if upper is True:
            MSG_ = message.upper()
        else:
            MSG_= message
        P = CLEF_.shape[0]

        # Encodage
        MATRIX = list()
        for i in range(0, len(MSG_), P):
            temp = list()
            groupe = MSG_[i:i+P]
            while len(groupe) != P:
                groupe += chr(np.random.randint(26)+65)
            
            for c in groupe:
                # temp.append(ord(c)-65)
                temp.append(alphabet[c])
            MATRIX.append(np.array(temp))

        # Chiffrement
        output = ""
        for vecteur in MATRIX:
            res = CLEF_.dot(vecteur)
            for i in range(res.shape[0]):
                # output += chr((res[i]%N)+65)
                output += get_keys_from_value(alphabet, (res[i]%N))
        
        #
        return output
    else:
        print('Error: Message or Key format is wrong')



def decrypt(message, clef, N=26, alphabet=Alphabet_mod26, upper=True):
    if type(message) is str and type(clef) is list:
        CLEF_ = Matrix(clef)
        try:
            CLEF_inv = CLEF_.inv_mod(N)
            if upper is True:
                MSG_ = message.upper()
            else:
                MSG_ = message
            P = CLEF_.shape[0]

            # Encodage
            MATRIX = list()
            for i in range(0, len(MSG_), P):
                temp = list()
                groupe = MSG_[i:i+P]
                while len(groupe) != P:
                    groupe += chr(np.random.randint(26)+65)
            
                for c in groupe:
                    # temp.append(ord(c)-65)
                    temp.append(alphabet[c])
                MATRIX.append(Matrix(temp))

            # Chiffrement
            output = ""
            for vecteur in MATRIX:
                res = CLEF_inv*(vecteur) % N
                for i in range(res.shape[0]):
                    # output += chr((res[i]%N)+65)
                    output += get_keys_from_value(alphabet, (res[i]%N))

            return output
        except:
            print("[-] Warning : The computed key ",clef,"for decryption is not invertible (mod ", N, ")")
            return None
    else:
        print('Error: wrong format of the message or the key')
        return None



def coincidence_index(encryptedText):
    #
    if (type(encryptedText) is str and encryptedText):
        #
        encryptedText = encryptedText.replace(" ", "").replace("\n","").upper()
        letter_count = dict(zip(string.ascii_uppercase, [0]*26))
        IC = 0
        N = len(encryptedText)

        # Frequency of each letter
        for key, values in letter_count.items():
            letter_count[key] = encryptedText.count(key)
     
        # Compute IC
        for key, values in letter_count.items():
            IC += (letter_count[key] * (letter_count[key] - 1)) / (N * (N - 1))
        
        return IC



#
def encode2matrix(data, dim, dictionary):
    L = []
    for i in range(0, len(data), dim):
        vector = []
        temp = data[i:i+dim]
        for c in temp:
            vector.append(dictionary[c])
        L.append(vector)
    return Matrix(L).T



#
def attack(message, key_length, crib, modulus=26, alphabet=Alphabet_mod26, upper=True):
    if (type(message) is str and type(crib) is str) and (len(crib) == key_length*key_length):
        #
        output = list()
        X = encode2matrix(crib, key_length, alphabet)
        try:
            X_inv = X.inv_mod(modulus)
            step = key_length*key_length
            for i in range(len(message)-step):
                temp = message[i:i+step]
                Y = encode2matrix(temp, key_length, alphabet)
              
                KEY = (Y*X_inv) % modulus
                
                res = decrypt(message, KEY.tolist(), modulus, alphabet, upper)
                if not res:
                    continue
                else:
                    IC = coincidence_index(res)
                    if IC > 0.04:
                        output.append((res, IC))

            return output
        except:
            return None
    else:
        print("Error args format : message and crib must be string type")
        return None