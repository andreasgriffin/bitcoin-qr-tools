# Bitcoin qr tools

* `BitcoinVideoWidget` recognizes (and classifies)  **blazingly fast**  
  * Addresses  (also BIP21 with amount)
  * Transactions (also base43 electrum encoding)
  * PSBT
  * Xpub
  * Descriptor
  * Multipath Descriptor (like Sparrow)
  * Partial descriptors (Specter DIY) (finger print , derivation, xpub)
  * TxId
  * Wallet Export Infos (Sparrow Format, Coldcard Sparrow QR format, Specter DIY, ...)
  * Animated QR Codes (BBQR)
  * Animated QR Codes ([UR](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-005-ur.md)) (Transactions, Descriptors, Jade Wallet Export)
  * Animated QR Codes (Specter)
  * Animated QR Codes (Foundation Passport)
* Recognizes (and classifies)  **blazingly fast**  
* QR Code generation via  `UnifiedEncoder.generate_fragments_for_qr()`
* QR Code Widgets, via the widgets `QRCodeWidget`,  `QRCodeWidgetSVG`

### Demo

Run the demo with

```
python demo_reader.py
```

### Detection even in bad light contitions and bad camera

![screenshot](docs/bad-light.png)

### Automatic image enhancement for bright hardware signer screens

![screenshot](docs/enhanced.png)

# Install package

### From pypi

```shell
pip install bitcoin_qr_tools
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
  python -m bitcoin_qr_tools
  ```

# Licences

The python files in *bitcoin_qr_tools*  are under the [GPL3](LICENSE).

The folder *bitcoin_qr_tools/ur* is from https://github.com/Foundation-Devices/foundation-ur-py  and under   [BSD-2-Clause Plus Patent License](ur/LICENSE).

The folder *bitcoin_qr_tools/urtypes* from https://github.com/selfcustody/urtypes  is under  [MIT](urtypes/LICENSE.md).
