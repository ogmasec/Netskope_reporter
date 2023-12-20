#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 
# README :

##### Import requests
import private.config as config
from modules.logger import *
#from modules.pdfGen import *
from modules.htmlGen import *
import requests
from time import sleep
import requests
import pandas as pd
import json
#####


class NetskopeAPI:
    def __init__(self):
        self.api_tenant = config.parse['params']['NSKP_TENANT_HOSTNAME'].lower()
        self.api_token = config.parse['params']['NSKP_TOKEN'].lower()
        self.api_url = config.parse['params']['NSKP_URL'].lower()
        self.url = self.api_tenant+self.api_url
        logger.info(self)

    def __str__(self):
        return f"Instanciation of object for tenant {self.url}..."

    def _request(self,endpoint, method="GET", params=None,  data=None):
        url = self.url + endpoint #endpoint is refered to the swagger
        logger.info(f"Endpoint: {url}?{params}")
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
    
    def get_dlp_incident(self,params_dlp,wait=5):
        # FAR : change the way off passing parameters
        dlp_response = self._request(config.parse['params']['NSKP_ALERTS_DLP'],params=f"operation={params_dlp['operation']}&index={params_dlp['index']}")
        
        if dlp_response is not None:
            try:
                dlp_response.raise_for_status()  # Check status
                logger.info(f"HTTP status code: {dlp_response.status_code} & wait time is {wait} secondes.")
                data = dlp_response.json()
            except requests.exceptions.HTTPError as e:
                logger.error(f"HTTP error: {e}")
                print("HTTP error:", e)
        else:
            logger.error(f"Error occurred during request: {dlp_response}.")
            print(f"Error occurred during request: {dlp_response}.")
        time.sleep(wait)
        return data

# Utilisation de la classe NetskopeAPI
if __name__ == "__main__":
    
    ### Get DLP Incidents ###
    nskp_dlp_incidents = NetskopeAPI()
    today = int(time.time())
    #FAR : Get args
    start = today-864000 # -10 days
    last = 0
    
    params_dlp = {"operation": str(start),"index":"PYSCRIPT_TAM_"+str(today)}
    dlp_incidents_list = nskp_dlp_incidents.get_dlp_incident(params_dlp)
    pause = dlp_incidents_list.get('wait_time')
    
    params_dlp = {"operation": "next","index":"PYSCRIPT_TAM"}
    """
    while last+3600 < today:
        if 'result' in dlp_incidents_list and isinstance(dlp_incidents_list['result'], list) and len(dlp_incidents_list['result']) != 0:
            dlp_incidents_list = nskp_dlp_incidents.get_dlp_incident(params_dlp,wait=pause)
            last = dlp_incidents_list.get('timestamp_hwm')
            pause = dlp_incidents_list.get('wait_time')
    """




   