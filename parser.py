import argparse
import sys

from pathlib import Path
from itertools import islice
from string import Formatter as Sfmt


DEFAULT_FORMAT = ('{date} {src} {dest} {protocol} {ttl} {tos} {id} {iplen} '
                  '{dgmlen} {ip_flags} {tcp_flags} {seq} {ack} {win} {tcplen} {len}')


def main():
    args = parse_args()
    input_file = args.input_file
    output_file = args.out_file # FIX
    fmt = args.format or DEFAULT_FORMAT
    add_header = args.header

    #if not input_file.is_absolute():
     #  input_file = input_file.absolute()
        
    if not input_file.exists():
        raise FileNotFoundError(f'{input_file} does not exist.')

    if output_file and output_file.exists():
        output_file = get_unused_name(output_file)

    parser = Parser()
    formatter = Formatter(fmt)

    with Reader(input_file) as reader, Writer(output_file) as writer:
        for count, lines in enumerate(reader.read_lines(5)):
            if add_header:
                writer.write(formatter.get_header())
                add_header = False
            data = parser.parse(lines)
            writer.write(formatter.format(data))
        print(f'Done! {count} events were written to {output_file or "console"}.')


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('input_file', type=Path, help='Path to input file')
    parser.add_argument('-o', '--out-file', type=Path, help='Path to output file')
    parser.add_argument('-f', '--format',
                        help='String constructed from lowered parameter names in curly brackets')
    parser.add_argument('-th', '--header', action='store_true', help='Prepend header to output')
    return parser.parse_args()

        
def get_unused_name(fn):
    counter = 1
    while True:
        new_name = fn.with_name(fn.stem + f'_{counter}' + fn.suffix)
        if not new_name.exists():
            return new_name
        counter += 1

    
class Reader:
    def __init__(self, path):
        self.fn = path

    def __enter__(self):
        self.file = open(self.fn)
        return self

    def __exit__(self, *args, **kwargs):
        self.file.close()

    def read_lines(self, n=1):
        while True:
            lines = [line.strip() for line in islice(self.file, n)]
            if not lines:
                break
            yield lines


class Parser:
    def parse(self, msg):
        parsed = {}

        parsed['date'], addr = msg[0].split(' ', maxsplit=1)
        parsed['src'], parsed['dest'] = self.parse_addr(addr)
        parsed.update(self.parse_ip(msg[1]))
        parsed.update(self.parse_transport(msg[2]))
        return parsed

    def parse_addr(self, addr):
        return addr.split(' -> ')

    def parse_ip(self, params_str):
        params = params_str.split(' ', maxsplit=6)
        named_params = {}
        for param in params[1:-1]:
            k, v = param.split(':')
            named_params[k.lower()] = v
        named_params['protocol'] = params[0]
        named_params['ip_flags'] = params[-1].split(' ')
        
        return named_params

    def parse_transport(self, params_str):
        params = params_str.split('  ')
        named_params = {}

        # If whitespace comes before colon, then we have TCP flags ***AP*** Seq: ...
        # Looks ugly, maybe I will rewrite it.
        if params[0].index(' ') < params[0].index(':'):
            named_params['tcp_flags'], params[0] = params[0].split(' ', maxsplit=1)

        for param in params:
            k, v = param.split(': ')
            named_params[k.lower()] = v

        return named_params
            
        
class Writer:
    def __init__(self, path=None):
        self.fn = path

    def __enter__(self):
        self.file = open(self.fn, 'a') if self.fn else sys.stdout
        return self

    def __exit__(self, *args, **kwargs):
        if self.file != sys.stdout:
            self.file.close()
  
    def write(self, data):
        self.file.write(data)
    

class Formatter:    
    def __init__(self, fmt):
        self.fmt = fmt

    def get_header(self):
        return ' '.join(meta[1].capitalize() for meta in Sfmt().parse(self.fmt)) + '\n'

    def format(self, data):
        return self.fmt.format_map(DefaultDict(data)) + '\n'


class DefaultDict(dict):
    def __init__(self, *args, **kwargs):
        self.default = kwargs.pop('default', None)
        super().__init__(*args, **kwargs)
         
    def __missing__(self, key):
        return self.default
    

if __name__ == '__main__':
    main()

        
        
        
        
