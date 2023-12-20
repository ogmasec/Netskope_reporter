#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 
# README :

##### Import requests
import private.config as config
from modules.logger import *
#from modules.pdfGen import *
from modules.htmlGen import *
from datetime import datetime
import requests
import time
import pandas as pd
import json
#####


class NetskopeAPI:
    def __init__(self):
        self.api_tenant = config.parse['params']['NSKP_TENANT_HOSTNAME'].lower()
        self.api_token = config.parse['params']['NSKP_TOKEN'].lower()
        self.api_url = config.parse['params']['NSKP_URL'].lower()
        self.url = self.api_tenant+self.api_url
        self.session = requests.Session()
        logger.info(self)

    def __str__(self):
        return f"Instanciation of object for tenant {self.url} with session {self.session}..."

    def _request(self,endpoint, params=None,  data=None):
        url = self.url + endpoint #endpoint is refered to the swagger
        logger.info(f"Endpoint: {url}?{params}")
        headers = {
            "Netskope-Api-Token": self.api_token,
            "Content-Type": "application/json"
        }
        
        #response = requests.request(
        response = self.session.get(
            #method=method,
            url=url,
            headers=headers,
            params=params,
            data=data
        )
        return response
    
    def get_dlp_incident(self,params_dlp,wait=5):
        # FAR : change the way off passing parameters
        dlp_response = self._request(
            config.parse['params']['NSKP_ALERTS_DLP'],
            params=f"operation={params_dlp['operation']}&index={params_dlp['index']}",

            )
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
        #time.sleep(wait)
        return data

# Utilisation de la classe NetskopeAPI
if __name__ == "__main__":
    
    ### Get DLP Incidents ###
    #FAR : Get args
    nskp_dlp_incidents = NetskopeAPI()
    now = int(time.time())
    start = now-864000 # -10 days
    #today = 1702631232 ## testing from
    pause = 5
    last = 0

    logger.info(f"start date :{datetime.fromtimestamp(start)} stop date: {datetime.fromtimestamp(now)}")
    operation = start
    while last+3600 < now:
        params_dlp = {"operation": operation,"index":"PYSCRIPT_TAM_"+str(now)}
        dlp_incidents_list = nskp_dlp_incidents.get_dlp_incident(params_dlp,wait=pause)
        last = dlp_incidents_list.get('timestamp_hwm')
        pause = dlp_incidents_list.get('wait_time')
        if 'result' in dlp_incidents_list and isinstance(dlp_incidents_list['result'], list) and len(dlp_incidents_list['result']) != 0:
            print(dlp_incidents_list)
            
        if operation != "next": ## change "opearion" from "head" to next
            operation = "next"
            logger.info(f"Operation is now 'Next'...")
    
    logger.info(f"Duration = {int(time.time())-now} secondes")




   