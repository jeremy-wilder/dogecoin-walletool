addrtypes = {
    'bitcoin': 0,
    'litecoin': 48,
    'namecoin': 52,
    'bitcoin-testnet': 111,
    'primecoin': 23,
    'dogecoin': 30,
    'dash': 76,
}

def show_private(v):
    if isinstance(v, bool):
       return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')
