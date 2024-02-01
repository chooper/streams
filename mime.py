#!/usr/bin/env python

"""
Decodes file containing MIME content

usage: mime.py [-h] -n NAME [-i INPUT] [-I {raw,hex,base64}] [-o OUTPUT] [-O {raw,hex,base64}]
"""

from sys import stdin, stdout
from streams import decode, encode, mime_extract
from streams import ENCODING_CHOICES


def main(args):
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
    
    # DO STUFF HERE
    # DO THIS HERE
    # YEAH

    output = mime_extract(args.name, decoded)

    # TODO maybe return a warning or an error?
    if not output:
        output = b''

    encoded = encode(output, args.output_encoding)
    output_fd.write(encoded)

    if real_input_file:
        input_fd.close()

    if real_output_file:
        output_fd.close()


if __name__ == '__main__':
    import argparse
    from sys import exit

    parser = argparse.ArgumentParser(description='Extract MIME data from a given file (or STDIN)')
    parser.add_argument('-n', '--name', help='name of mime entry to extract', required=True)

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