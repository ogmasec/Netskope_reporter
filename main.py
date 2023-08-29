#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 
# README :

##### Import requests
import private.config as config
from modules.logger import *
import time
from datetime import datetime
import requests
#####


class NetskopeAPI:
    def __init__(self, base_url, api_token):
        self.base_url = base_url
        self.api_token = api_token

    def make_request(self, endpoint, method="GET", params=None,  data=None):
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
    operation = "head"
    netskope_api = NetskopeAPI(api_base_url, api_token)
    
    
    def _getData(operation):
        response = netskope_api.make_request("", params={"operation": operation, "index": "reporter"})
        if response is not None:
            try:
                response.raise_for_status()  # Check status
                data = response.json()
                logger.info(f"API Response: {data}")
                # print("API Response:", data)
            except requests.exceptions.HTTPError as e:
                logger.error(f"HTTP error: {e}")
                print("HTTP error:", e)
        else:
            logger.error(f"Error occurred during request: {response}.")
            print(f"Error occurred during request: {response}.")
        return data
 

    def _extractFields(data,selected_fields) :
        # Extracting fields
        # selected_fields = []
        wait_time = data["wait_time"]
        for entry in data['result']:
            timestamp_epoch = entry['timestamp']
            timestamp_readable = datetime.fromtimestamp(timestamp_epoch).strftime('%Y-%m-%d %H:%M:%S')
            selected_fields.append({
                'timestamp': entry['timestamp'],
                'Date (converted)': timestamp_readable,
                '_id': entry['_id'],
                'alert_name' : entry['alert_name'],
                'alert_type' : entry['alert_type'],
                'dlp_incident_id' : entry['dlp_incident_id'],
                'dlp_profile' : entry['dlp_profile'],
                'dlp_rule' : entry['dlp_rule'],
                'policy' : entry['policy'],
                'scan_type' : entry['scan_type'],
                'sha256': entry['sha256'],
                'title': entry['title']
            })
        # Printing extracted fields
        return selected_fields, wait_time
    
    selected_fields = []
    while True:
        response = _getData(operation)
        if 'result' in response and isinstance(response['result'], list) and len(response['result']) == 0:
            print("No more data...")
            logger.info("No more data...")
            break
        selected_fields,wait= _extractFields(response,selected_fields)
        operation = "next"
        logger.info(f"Waiting {wait+1} seconds for API rate limiting...")
        time.sleep(wait+1)

    num_rows = len(selected_fields)
    print("Total DLP alerts=", num_rows)
    logger.info(f"Total DLP alerts={num_rows}")   
    print("{:<5} {:<5} {:<5} {:<5} {:<5} {:<5}".format("Timestamp", "Date (converted)", "_id", "Alert Name", "Alert Type", "Scan type","Title"))
    print("="*100)

    for item in selected_fields:
        print("{:<5} {:<5} {:<5} {:<5} {:<5} {:<5}".format(
        item['timestamp'], item['Date (converted)'], item['_id'], item['alert_name'], item['alert_type'], item['scan_type'], item['title']))