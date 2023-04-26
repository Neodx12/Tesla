import os

import hashlib

import ecdsa

import base58

import requests

import time

# Define a list of API endpoints to use

api_endpoints = [

    "https://api.blockcypher.com/v1/btc/main/addrs/{}/balance",

    "https://api.smartbit.com.au/v1/blockchain/address/{}/balance",

    "https://chain.api.btc.com/v3/address/{}/balance",

]

def check_balance(address):

    # Try each API endpoint in the list until one succeeds

    for api_endpoint in api_endpoints:

        # Format the API URL with the address

        api_url = api_endpoint.format(address)

        # Make the request and handle errors

        while True:

            try:

                response = requests.get(api_url)

            except requests.exceptions.ConnectionError:

                print("Connection error, retrying in 3 seconds...")

                time.sleep(3)

                continue

            # Parse the response and return the balance in satoshis

            if response.status_code == 200:

                response_json = response.json()

                return response_json["final_balance"]

            elif response.status_code == 429:

                print("Rate limit exceeded, retrying in 60 seconds...")

                time.sleep(60)

            else:

                break

    return None

while True:

    # Generate a random 256-bit number

    private_key = int.from_bytes(os.urandom(32), byteorder="big")

    # Check that the number is a valid ECDSA private key

    curve = ecdsa.curves.SECP256k1

    order = curve.order

    if private_key > 0 and private_key < order:

        # Compute the corresponding public key

        sk = ecdsa.SigningKey.from_secret_exponent(private_key, curve=curve)

        vk = sk.get_verifying_key()

        public_key = vk.to_string("compressed")

        # Compute the corresponding Bitcoin address

        ripemd160 = hashlib.new("ripemd160")

        ripemd160.update(hashlib.sha256(public_key).digest())

        hashed_public_key = ripemd160.digest()

        version = b"\x00"  # Mainnet

        payload = version + hashed_public_key

        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

        address = base58.b58encode(payload + checksum).decode("utf-8")

        # Check the balance of the address

        balance = check_balance(address)

        print("Private key:", hex(private_key))

        print("Public key:", public_key.hex())

        print("Bitcoin address:", address)

        if balance is not None:

            print("Balance:", balance, "satoshis")

        else:

            print("Failed to check balance")

        if balance is not None and balance > 0:

            # If the balance is non-zero, exit the loop

            break

