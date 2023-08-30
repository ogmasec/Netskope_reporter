﻿#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 
# README :

##### Import requests
import private.config as config
from modules.logger import *
from modules.pdfGen import *
from modules.htmlGen import *
import time
from datetime import datetime
import requests
import pandas as pd
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
 

    def _extractFields(data, selected_fields):
        wait_time = data["wait_time"]
        for entry in data['result']:
            timestamp_epoch = entry['timestamp']
            timestamp_readable = datetime.fromtimestamp(timestamp_epoch).strftime('%Y-%m-%d %H:%M:%S')

            dlp_incident_id = entry['dlp_incident_id']
            
            # Extracting dlp_rules
            dlp_rules = []
            for rule in entry.get('dlp_match_info', []):
                for dlp_rule in rule.get('dlp_rules', []):
                    dlp_rules.append({
                        'dlp_rule_name': dlp_rule.get('dlp_rule_name', ''),
                        'dlp_rule_score': dlp_rule.get('dlp_rule_score', ''),
                        'dlp_rule_severity': dlp_rule.get('dlp_rule_severity', ''),
                    })

            activity = entry.get('activity', '')

            selected_fields.append({
                'Date (converted)': timestamp_readable,
                'dlp_incident_id': dlp_incident_id,
                'dlp_rules': dlp_rules,
                'activity': activity,
            })
    
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

    '''

    print("{:<15} {:<25} {:<20} {:<50} {:<15} {:<20} {:<20} {:<20} {:<20} {:<15} {:<40}".format(
        "Timestamp", "Date (converted)", "_id", "Alert Name", "Alert Type", "DLP Incident ID",
        "DLP Profile", "DLP Rule", "Policy", "Scan Type", "Title"
    ))
    print("="*240)

    for item in selected_fields:
        print("{:<15} {:<25} {:<20} {:<50} {:<15} {:<20} {:<20} {:<20} {:<20} {:<15} {:<40}".format(
            item['timestamp'], item['Date (converted)'], item['_id'], item['alert_name'], item['alert_type'],
            item['dlp_incident_id'], item['dlp_profile'], item['dlp_rule'], item['policy'], item['scan_type'], item['title']
        ))
    
    '''


    pdf_generator = PDFGenerator("data_table.pdf")
    pdf_generator.generate_pdf(selected_fields)
    
    
    
    # Liste des colonnes pour le tableau
    columns = ["Date (converted)", "Incident ID", "DLP Rule Name", "DLP Rule Score", "DLP Rule Severity", "Activity"]

    # Générer le fichier HTML
    html_generator = HTMLGenerator("report.html", columns)
    for item in selected_fields:
        html_generator.add_data(
            Date=item.get("Date (converted)", ""),
            Incident_ID=item.get("dlp_incident_id", ""),
            DLP_Rule_Name=item.get("dlp_rules", [{}])[0].get("dlp_rule_name", ""),
            DLP_Rule_Score=str(item.get("dlp_rules", [{}])[0].get("dlp_rule_score", "")),
            DLP_Rule_Severity=item.get("dlp_rules", [{}])[0].get("dlp_rule_severity", ""),
            Activity=item.get("activity", "")
        )
    html_generator.generate_html()
