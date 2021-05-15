import argparse
from walletool.wallet_files import read_wallet_dat
from walletool.wallet_items import parse_wallet_dict, KeyWalletItem
from walletool.consts import addrtypes, show_private

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('-d', '--dat', help='wallet.dat path', required=True, dest='filename')
    ap.add_argument('-p', '--show_private', help='show private keys',  default=False, type=show_private, nargs='?',const=True)
    ap.add_argument('-v', '--version', help='address version, as integer, 0xHEX, or any of the following known coins:\n[%s]' % ', '.join(sorted(addrtypes)), required=False)
    args = ap.parse_args()

    if args.version:
        if args.version.startswith('0x'):
            version = int(args.version[2:], 16)
        elif args.version.isdigit():
            version = int(args.version)
        else:
            if args.version not in addrtypes:
                raise ValueError('invalid version (see --help)')
    else:
        version = 30

    w_data = read_wallet_dat(args.filename)
    addr_tuples = []
    for item in parse_wallet_dict(w_data):
        if isinstance(item, KeyWalletItem):
            address = item.get_address(version=version)
            uncompressed = item.get_uncompressed(version=version)
            privkey = item.get_private_key(version=version)
            addr_tuples.append((address, uncompressed, privkey))
    for address, uncompressed, privkey in addr_tuples:
        if args.show_private:
            print(address, uncompressed, privkey)
        else:
            print(address)
            print(uncompressed)

if __name__ == '__main__':
    main()
