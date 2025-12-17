# MTProto MITM server

Telegram mtproto mitm server.<br>

**This project must be used for research purposes only.**

## Installation
**Requirements:**
  - Python 3.11+

```shell
pip install mtproto-mitm
```

# TODO
  - [ ] Record mtproto connections to files to allow reviewing them later
  - [x] Add cli interface
  - [ ] Add web interface ?

## Usage

1. Install mtproto-mitm
2. Get your telegram auth key:
    - Telethon or Pyrogram: you need session file and any sqlite reader. Open session file with sqlite reader and run "SELECT HEX(auth_key) FROM sessions;"
    - Telegram for Android (not Telegram X): you need root access. Copy tgnet.dat file from telegram directory (/data/data/\<package name\>/files/tgnet.dat) from your android device to your pc. Now you can use [tgnet](https://github.com/RuslanUC/tgnet) to extract key: use code from [example](https://github.com/RuslanUC/tgnet).
    - Telegram Desktop: you can use [opentele](https://github.com/thedemons/opentele) to extract auth key from tdata folder. From Telegram Desktop version 5 and newer, seems like Telegram uses exclusively temp auth keys that are generated at runtime and not stored anywhere; that means once you close Telegram Desktop application, you won't be able to access decryption keys, so you need to extract them from memory while Telegram is running, and only then start mtproto-mitm with those keys; also, note that temp keys work for at most 1 day (iirc) and even if you won't restart Telegram application, you'll need to extract keys again later. To extract keys from memory, you can use [tdesktop-keys-extract script](https://github.com/RuslanUC/tdesktop-keys-extract).
3. Run MTProto-MITM:

    ```shell
    Usage: python -m mtproto_mitm [OPTIONS]
    
    Options:
      -h, --host TEXT       Proxy host to run on.
      -p, --port INTEGER    Proxy port to run on.
      -k, --key TEXT        Hex-encoded telegram auth key.
      -f, --keys-file TEXT  File with telegram auth keys.
      -q, --quiet           Do not show requests in real time.
      -o, --output TEXT     Directory to which mtproto requests will be saved.
      --proxy-no-auth       Disable authentication for proxy.
      --proxy-user TEXT     Proxy user in login:password format.
      --help                Show this message and exit.
    ```

4. Set socks5 proxy settings on your telegram client to host/port/user you specified on last step.

## Examples
```shell
python -m mtproto_mitm --host 127.0.0.1 --port 1080 --key 0F5B...A38F --keys-file ./auth_keys
```
