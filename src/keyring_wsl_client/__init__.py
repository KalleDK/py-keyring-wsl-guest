__author__ = "Kalle M. Aagaard <git@k-moeller.dk>"
__version__ = "0.3.4"

import json
import subprocess

from typing import TypedDict


import keyring.backend
import keyring.credentials

class CredResult(TypedDict):
    username: str
    password: str


class WSLProxyBackend(keyring.backend.KeyringBackend):

    priority = 9.9 # type: ignore


    def __init__(self):
        self._cache: dict[tuple[str, str], str] = {}

    def _run(self, *args: str):
        r = subprocess.run(["keyring-host.exe", *args], capture_output=True)
        return json.loads(r.stdout.decode().strip())["result"]

    def get_credential(self, service: str, username: str | None):
        args = [service]
        if username is not None:
            args.append(username)
        cred: CredResult | None  = self._run("cred", *args)
        
        if cred is None:
            return None

        self._cache[service, cred["username"]] = cred["password"]
        return keyring.credentials.SimpleCredential(cred["username"], cred["password"])


    def get_password(self, service: str, username: str):
        password = self._cache.get((service, username), None)
        if password is not None:
            return password

        creds = self.get_credential(service, None)
        if creds and username == creds.username:
            return creds.password

        return None


    def set_password(self, service: str, username: str, password: str):
        self._run("set", service, username, password)

    def delete_password(self, service: str, username: str):
        self._run("del", service, username)
