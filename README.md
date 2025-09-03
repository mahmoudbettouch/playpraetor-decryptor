# PlayPraetor Android Malware Decryptor

This scripts extract the apk payload from the PlayPraetor dropper, it works on all versions of the malware using a dropper to install a second stage apk.

I wrote this script to help me keep up with the new C2 they deploy, and it was a tedious work to open the apk in jadx, export the assets/base directory, then get the keys and decrypt them. So this script will do all of that automatically from a given apk sample.


## Requirements

I had to modify the axmlparserpy library to be compatible with Python 2. To avoid conflicts, I included the patched version directly in this repository. It's a simplest solution I found that works.

```
pip install -r requirements
```

## Usage 

```
python playpraetor-decryptor.py <apk_file>
```
