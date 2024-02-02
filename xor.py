#!/usr/bin/env python

"""
Usage: xor.py [-h] [-K {raw,hex,base64}] [-i INPUT] [-I {raw,hex,base64}] [-o OUTPUT] [-O {raw,hex,base64}] key
"""

from sys import stdin, stdout
from streams import decode, encode, xor_bytes
from streams import ENCODING_CHOICES


def main(args):
    args.key = args.key.encode()
    args.key = decode(args.key, args.key_encoding)

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
    
    output = xor_bytes(args.key, decoded, args.offset)

    encoded = encode(output, args.output_encoding)
    output_fd.write(encoded)

    if real_input_file:
        input_fd.close()

    if real_output_file:
        output_fd.close()


if __name__ == '__main__':
    import argparse
    from sys import argv, exit

    parser = argparse.ArgumentParser(description='XOR an input with a given KEY')
    parser.add_argument('key', help='key used for the XOR operation')
    parser.add_argument('-K', '--key-encoding', help='encoding used for key',
                        choices=ENCODING_CHOICES, default='raw')
    parser.add_argument('-f', '--offset', help='where in input to begin XOR operation. negative numbers result in input prepended with \\xFF. useful for alignment issues.',
                        type=int, default=0)
    parser.add_argument('-i', '--input', help='file to read or - for STDIN', default='-')
    parser.add_argument('-I', '--input-encoding', help='encoding used for input file',
                        choices=ENCODING_CHOICES, default='raw')
    
    parser.add_argument('-o', '--output', help='file to write to or - for STDOUT', default='-')
    parser.add_argument('-O', '--output-encoding', help='encoding used for output file',
                        choices=ENCODING_CHOICES, default='raw')
    
    args = parser.parse_args()

    try:
        main(args)
    except (KeyboardInterrupt, SystemExit):
        exit(0)