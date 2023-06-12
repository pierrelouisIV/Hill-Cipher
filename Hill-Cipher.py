# -*- coding: utf-8 -*-
# _authors_: Petrus
# _date_ : 12/06/2023

from utils.utils import *


def main(args):
    # Inputs
    data = args.text
    mode = args.mode
    dico = eval(args.dico)
    
    #
    output = None
    outputs = None

    if mode == "attack":
        crib = args.crib
        p = args.p
        # Launch the plaintext attack
        print("[+] Plaintext attack processing ...")
        outputs = attack(data, p, crib, len(dico), dico, False)
    elif mode == "enc":
        # Encryption
        print("[+] Encryption processing ...")
        key = eval(args.key)
        output = encrypt(data, key, len(dico), dico, False)
    elif mode == "dec":
        # Decryption
        print("[+] Decryption processing ...")
        key = eval(args.key)
        output = decrypt(data, key, len(dico), dico, False)

    #
    if (output):
        print("[+] Done")
        print("|-> ", output)
    elif (outputs):
        print("[+] Done")
        print("[+] Message(s) with letters which are not distributed evenly (IC > 0.05)")
        for res in outputs:
            print("|->",res[0]," || IC = ", res[1])
    elif (not outputs):
        print("[+] Done")
        print(outputs)
        print("[+] No message(s) found, try with an other crib")
    




if __name__ == '__main__':
	print(Banner)
	main(parse_args())