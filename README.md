# A python bitcoin qr reader

* Recognizes (and classifies)
  * Addresses  (also BIP21 with amount)
  * Transactions (also base43 electrum encoding)
  * PSBT
  * Xpub
  * Descriptor
  * Partial descriptors (Specter DIY) ( finger print , derivation, xpub)
  * TxId
* **blazingly fast** recognition
* bdkpython as only bitcoin dependency
* SLIP132 -> to BIP32 conversion

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



###  From git

```shell
python setup.py sdist bdist_wheel
pip install dist/bitcoin_qrreader*.whl  
```



