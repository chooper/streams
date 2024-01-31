#!/usr/bin/env python

"""
usage: aes.py [-h] [-K {raw,hex,base64}] [-v IV] [-V {raw,hex,base64}] [-i INPUT] [-I {raw,hex,base64}] [-o OUTPUT] [-O {raw,hex,base64}] [-e] [-d] key
"""

from sys import stdin, stdout, stderr
from streams import decode, encode, aes_decrypt, aes_encrypt
from streams import ENCODING_CHOICES


def main(args):
    args.key = bytearray(args.key, 'ascii')
    args.key = decode(args.key, args.key_encoding)

    if args.iv:
        args.iv = bytearray(args.iv, 'ascii')
        args.iv = decode(args.iv, args.iv_encoding)

    real_input_file = False
    if args.input == '-':
        input_fd = stdin.buffer
    else:
        real_input_file = True
        input_fd = open(args.input, 'br')

    real_output_file = False
    if args.output == '-':
        output_fd = stdout.buffer
    else:
        real_output_file = True
        output_fd = open(args.output, 'bw+')

    input = input_fd.read()
    decoded = decode(input, args.input_encoding)

    if args.decrypt:    
        output = aes_decrypt(decoded, args.key, args.iv)
    
    if args.encrypt:
        output = aes_encrypt(decoded, args.key, args.iv)

    encoded = encode(output, args.output_encoding)
    output_fd.write(encoded)

    if real_input_file:
        input_fd.close()

    if real_output_file:
        output_fd.close()


if __name__ == '__main__':
    import argparse
    from sys import exit

    # TODO: configurable block size?
    parser = argparse.ArgumentParser(description='AES an input with a given KEY and IV')
    parser.add_argument('key', help='key used for the AES operation')
    parser.add_argument('-K', '--key-encoding', help='encoding used for key',
                        choices=ENCODING_CHOICES, default='raw')

    parser.add_argument('-v', '--iv', help='iv used for the AES operation')
    parser.add_argument('-V', '--iv-encoding', help='encoding used for IV',
                        choices=ENCODING_CHOICES, default='raw')

    parser.add_argument('-i', '--input', help='file to read or - for STDIN', default='-')
    parser.add_argument('-I', '--input-encoding', help='encoding used for input file',
                        choices=ENCODING_CHOICES, default='raw')
    
    parser.add_argument('-o', '--output', help='file to write to or - for STDOUT', default='-')
    parser.add_argument('-O', '--output-encoding', help='encoding used for output file',
                        choices=ENCODING_CHOICES, default='raw')
    
    parser.add_argument('-e', '--encrypt', help='encrypt input (default)', action='store_true', default=False)
    parser.add_argument('-d', '--decrypt', help='decrypt input', action='store_true', default=False)

    args = parser.parse_args()

    # todo: output usage
    if args.encrypt and args.decrypt:
        stderr.write("Only encryption or decryption can be selected; not both.\n")
    
    # if not args.encrypt and not args.decrypt:
        # stderr.write("An encryption operation (encrypt or decrypt) must be selected.\n")

    if not args.decrypt:
        args.encrypt = True

    try:
        main(args)
    except (KeyboardInterrupt, SystemExit):
        exit(0)