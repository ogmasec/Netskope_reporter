#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 
# README :

##### Import requests
import private.config as config
from modules.logger import *
import time
import requests
#####


class NetskopeAPI:
    def __init__(self, base_url, api_token):
        self.base_url = base_url
        self.api_token = api_token

    def make_request(self, endpoint, method="GET", params=None, data=None):
        url = self.base_url + endpoint

        headers = {
            "Netskope-Api-Token": self.api_token,
            "Content-Type": "application/json"
        }

        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            params=params,
            data=data
        )

        return response

# Utilisation de la classe NetskopeAPI
if __name__ == "__main__":
    api_tenant = config.parse['params']['NSKP_TENANT_HOSTNAME'] 
    api_token = config.parse['params']['NSKP_TOKEN'] 
    api_url = config.parse['params']['NSKP_DLP'] 
    api_base_url = api_tenant+api_url
    api_client = NetskopeAPI(api_base_url, api_token)

    response = api_client.make_request("", params={"operation": "head", "index": "reporter"})

    if response.status_code == 200:
        data = response.json()
        print("API Response:", data)
    else:
        print("Error:", response.status_code)
