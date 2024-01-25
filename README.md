# A python bitcoin qr reader

* Recognizes (and classifies)
  * Addresses  (also BIP21 with amount)
  * Transactions (also base43 electrum encoding)
  * PSBT
  * Xpub
  * Descriptor
  * Multipath Descriptor (like Sparrow)
  * Partial descriptors (Specter DIY) ( finger print , derivation, xpub)
  * TxId
  * Animated QR Codes ([UR](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md)) (Transactions and Descriptors)
  * Animated QR Codes (Specter)
* **blazingly fast** recognition
* SLIP132 --> BIP32 conversion (output descriptors replace SLIP132)

### Demo

Run the demo with

```
python demo.py
```

![screenshot](docs/screenshot.png)

# Install package



### From pypi

```shell
pip install bitcoin_qrreader
```

### From git

 * Setup poetry and install dependencies 

   ```sh
   curl -sSL https://install.python-poetry.org | python3 -  # see https://python-poetry.org/docs/master/#installing-with-the-official-installer
   poetry config virtualenvs.in-project true
   poetry install
   ```


 * Run  

   ```sh
   poetry shell
   python -m bitcoin_qrreader
   ```
   



# Licences

The python files in *bitcoin_qrreader*  are under the [GPL3](LICENSE).

The folder *bitcoin_qrreader/ur* is from https://github.com/Foundation-Devices/foundation-ur-py  and under   [BSD-2-Clause Plus Patent License](ur/LICENSE).

The folder *bitcoin_qrreader/urtypes* from https://github.com/selfcustody/urtypes  is under  [MIT](urtypes/LICENSE.md).
