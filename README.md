doge walletool ~ a tool for reading dogecoin wallet.dat files
==============================================================

Tool is forked from akx/walletool to read dogecoin-qt wallet.dat files.  It lists all compressed and uncompressed public keys to check the balance against [dogechain.info](https://www.dogechain.info/ "dogechain.info") API.  If a balance is found use the `-p Y` option on wt_extract_keys.py to show the private key.

**doge welcome** - DHYPo1kHGxpAQBcPnsD3MZEr2NT399WwUC


Installation
------------

* Install Python 3.x.
* Install the `bsddb3` module (if you're on Windows, use Gohlke's site).

Extracting public keys from Dogecoin-QT wallets
-----------------------------------------------

* Have your `wallet.dat` handy.
* Run `python wt_extract_keys.py -d wallet.dat`

A list of dogecoin compressed / uncompressed public keys are printed.

Extracting public & private keys from Dogecoin-QT wallets
-----------------------------------------------------------

* Run `python wt_extract_keys.py -d wallet.dat -p Y`


Checking Dogecoin-QT wallet balances
------------------------------------

* Run `python wt_extract_keys.py -d wallet.dat > public_keys.dat`
* Run `python check_dogechain.py public_keys.dat > balance.dat`


