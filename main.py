# -*- coding: utf-8 -*-

import os
import configparser
import os
import multiprocessing
import platform

from tkinter import filedialog
from time import time

import utils
import utils_crypto

if __name__ == "__main__":
    # multiprocessing
    multiprocessing.freeze_support()
    cores = multiprocessing.cpu_count() - 1

    # title
    utils.set_title(f"Gataka Wallet Checker")

    # enable ansi
    system_type = platform.system()
    if system_type == "Windows":
        os.system("color")

    # results
    dir = utils.get_file_path(f"results")
    if not os.path.exists(dir):
        os.makedirs(dir)

    # results files
    timestamp = int(time())
    path_results = utils.get_file_path(f"results/results_{timestamp}.xlsx")
    path_errors = utils.get_file_path(f"results/errors_{timestamp}.txt")

    # config
    config = configparser.ConfigParser()
    config.read(utils.get_file_path("settings.ini"))
    depth_public_addresses = int(config["DEPTH"]["public_addresses"])
    depth_private_keys = int(config["DEPTH"]["private_keys"])
    is_skip_ledger = config["HARDWARE"].getboolean("skip_ledger")
    is_skip_trezor = config["HARDWARE"].getboolean("skip_trezor")
    is_parse_mnemonics = config["CHECKER"].getboolean("parse_mnemonics")
    is_browser_wallets = config["CHECKER"].getboolean("browser_wallets")
    is_browser_wallets_ldb = config["CHECKER"].getboolean("browser_wallets_ldb")
    is_core_wallets = config["CHECKER"].getboolean("core_wallets")
    is_exodus = config["CHECKER"].getboolean("exodus")
    is_electrum = config["CHECKER"].getboolean("electrum")
    is_multibit = config["CHECKER"].getboolean("multibit")
    is_blockchain = config["CHECKER"].getboolean("blockchain")
    is_monero = config["CHECKER"].getboolean("monero")
    is_coinomi = config["CHECKER"].getboolean("coinomi")
    is_keystroke = config["CHECKER"].getboolean("keystroke")
    is_atomic = config["CHECKER"].getboolean("atomic")
    is_phantom = config["CHECKER"].getboolean("phantom")
    is_trust = config["CHECKER"].getboolean("trust")
    is_bads = config["MAIN"].getboolean("process_bads")
    rules_path = config["MAIN"]["path_rules"]
    if rules_path == "-":
        rules_path = False
    else:
        if not os.path.exists(rules_path) or not rules_path.endswith(".rule"):
            rules_path = False

    # mode select
    utils.clear()
    print("[1] Check logs")
    print("[2] Brute wallet [Dictionary Attack]")
    print("[3] Brute wallet [Mask Attack]")
    user_input = input("\nMode: ")
    utils.clear()

    # mode start
    if user_input == "1":
        path_source = filedialog.askdirectory(title="Select folder with logs")
        time_start = time()
        utils_crypto.checker(
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
        )
        time_end = time()
        time_total = int(time_end - time_start)
        input(f"\nTask completed in {time_total} seconds...")
    elif user_input == "2":
        hash = input("Hash: ")
        hash_mode = input("Hash mode: ")
        path_dict = input("Dictionary path: ")
        password = utils_crypto.hashcat(hash_mode, hash, path_dict, False, False)
        if password and password != "-":
            utils.print_green(f"Password cracked! Password: {password}\n")
        else:
            utils.print_red(f"Brute failed")

        input(f"\nTask completed...")

    elif user_input == "3":
        hash = input("Hash: ")
        hash_mode = input("Hash mode: ")
        path_mask = input("Mask path: ")
        password = utils_crypto.hashcat(hash_mode, hash, False, path_mask, False)
        if password and password != "-":
            utils.print_green(f"Password cracked! Password: {password}\n")
        else:
            utils.print_red(f"Brute failed")

        input(f"\nTask completed...")
