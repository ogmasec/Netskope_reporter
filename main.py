#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 
# README :

##### Import requests
import private.config as config
from modules.logger import *
#from modules.pdfGen import *
from modules.htmlGen import *
import time
from datetime import datetime
import requests
import pandas as pd
import json
#####


class NetskopeAPI:
    def __init__(self, base_url,api_token):
        self.base_url = base_url
        self.api_token = api_token
        self.endpoint = endpoint

    def __str__(self):
        return f"Connection established on {self.base_url} with endpoint {self.endpoint}"

    def make_request(self, method="GET", params=None,  data=None):
        url = self.base_url + self.endpoint
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
    
    def get_dlp_incident(self):
        self.make_request
    
        

# Utilisation de la classe NetskopeAPI
if __name__ == "__main__":
    api_tenant = config.parse['params']['NSKP_TENANT_HOSTNAME'] 
    api_token = config.parse['params']['NSKP_TOKEN'] 
    api_url = config.parse['params']['NSKP_URL']
    endpoint = config.parse['params']['NSKP_DLP']
    #endpoint = config.parse['params']['NSKP_event_alert']
    
    api_base_url = api_tenant+api_url
    operation = "head"
    nskp_alerts = NetskopeAPI(api_base_url,endpoint, api_token)
    logger.info(nskp_alerts)
    
    def _getData(operation):
        #OFFLINE
        #response = nskp_alerts.make_request(params={"operation": operation, "index": "reporter"})
        #######
        data = {'ok': 1, 'result': [{'_id': '5a404cd42cc4569271a134df', 'access_method': 'Client', 'acked': 'false', 'action': 'block', 'activity': 'Download', 'alert': 'yes', 'alert_name': 'block AMBER files', 'alert_type': 'DLP', 'app': 'Google Drive', 'app_session_id': 3274852309203609531, 'appcategory': 'Cloud Storage', 'appsuite': 'Google App', 'browser': 'Chrome', 'browser_session_id': 5643715785204764860, 'browser_version': '117.0.0.0', 'category': 'Cloud Storage', 'ccl': 'high', 'connection_id': 6891632877782369926, 'device': 'Windows Device', 'device_classification': 'not configured', 'dlp_file': 'amber DLP.docx.pdf', 'dlp_incident_id': 5659215261472516453, 'dlp_is_unique_count': 'false', 'dlp_parent_id': 5659215261472516453, 'dlp_profile': 'DLP Ogmasec Amber', 'dlp_rule': 'Ogmasec Amber rule', 'dlp_rule_count': 1, 'dlp_rule_severity': 'Low', 'dst_country': 'US', 'dst_latitude': 34.035, 'dst_location': 'Colbert', 'dst_longitude': -83.2191, 'dst_region': 'Georgia', 'dst_timezone': 'America/New_York', 'dst_zipcode': '30628', 'dstip': '142.250.179.97', 'file_lang': 'Unknown', 'file_size': 12773, 'file_type': 'application/pdf', 'from_user': 'mathieu.guerin@ogmasec.fr', 'hostname': 'PC', 'incident_id': 899404351323158813, 'instance_id': 'ogmasec.fr', 'managed_app': 'no', 'managementID': '', 'md5': '5b8b9381043d8576a8f88bbc9f2b0999', 'object': 'amber DLP.docx.pdf', 'object_id': '1XWEGhZHEizUjHzv4dpdRJSNZr-wpRPJk', 'object_type': 'File', 'organization_unit': '', 'os': 'Windows 11', 'os_version': 'Windows 11', 'page': 'drive.usercontent.google.com', 'page_site': 'Google Drive', 'policy': 'block AMBER files', 'policy_id': '7B5C019A7148AA500AB5E1426EB7EB19 2023-09-15 14:16:24.904568', 'protocol': 'HTTPS/1.1', 'request_id': 2667823107070723584, 'sanctioned_instance': 'Yes', 'scan_type': '', 'severity': 'unknown', 'sha256': 'b5081cf9e1bffacee320bc4b0878013ad5de2003615b8d75fefcc86637d98474', 'site': 'Google Drive', 'src_country': 'FR', 'src_latitude': 43.4951, 'src_location': 'Bayonne', 'src_longitude': -1.4739, 'src_region': 'Nouvelle-Aquitaine', 'src_time': 'Mon Sep 18 14:53:16 2023', 'src_timezone': 'Europe/Paris', 'src_zipcode': '64100', 'srcip': '91.160.73.239', 'timestamp': 1695041643, 'title': 'amber DLP.docx.pdf', 'traffic_type': 'CloudApp', 'transaction_id': 899404351323158813, 'true_obj_category': 'Word Processor', 'true_obj_type': 'Adobe Portable Document Format (PDF)', 'true_type_id': 230, 'tss_mode': 'inline', 'type': 'nspolicy', 'ur_normalized': 'mguerin@netskope.com', 'url': 'drive.usercontent.google.com/download', 'user': 'mguerin@netskope.com', 'userip': '192.168.1.59', 'userkey': 'mguerin@netskope.com', 'classification_name': '', 'message_id': '', 'universal_connector': '', 'dst_geoip_src': 0, 'user_id': '', 'external_collaborator_count': 0, 'file_path': '', 'userPrincipalName': '', 'src_geoip_src': 0, 'group': '', 'web_universal_connector': '', 'file_category': '', 'channel': '', 'sAMAccountName': '', 'dlp_fingerprint_score': 0, 'retro_scan_name': '', 'dlp_fingerprint_match': '', 'true_filetype': '', 'message_size': 0, 'total_collaborator_count': 0, 'dlp_unique_count': 0, 'instance': '', 'to_storage': '', 'dlp_rule_score': 0, 'data_type': '', 'owner': '', 'from_storage': '', 'app_activity': '', 'violating_user': '', 'file_password_protected': '', 'dynamic_classification': '', 'parent_id': '', 'dlp_fingerprint_classification': '', 'bcc': '', 'outer_doc_type': 0, 'mime_type': '', 'owner_pdl': '', 'smtp_to': [], 'userCountry': '', 'exposure': '', 'shared_with': '', 'mail': '', 'shared_domains': '', 'file_cls_encrypted': False, 'manager': '', 'dlp_mail_parent_id': '', 'to_user': '', 'suppression_key': '', 'orignal_file_path': '', 'local_sha256': '', 'violating_user_type': '', 'act_user': '', 'sub_type': '', 'modified': 0, 'referer': '', 'collaborated': '', 'displayName': ''},{'_id': '5a404cd42cc4569271a134df', 'access_method': 'Client', 'acked': 'false', 'action': 'block', 'activity': 'Download', 'alert': 'yes', 'alert_name': 'block AMBER files', 'alert_type': 'DLP', 'app': 'Google Drive', 'app_session_id': 3274852309203609531, 'appcategory': 'Cloud Storage', 'appsuite': 'Google App', 'browser': 'Chrome', 'browser_session_id': 5643715785204764860, 'browser_version': '117.0.0.0', 'category': 'Cloud Storage', 'ccl': 'high', 'connection_id': 6891632877782369926, 'device': 'Windows Device', 'device_classification': 'not configured', 'dlp_file': 'amber DLP.docx.pdf', 'dlp_incident_id': 9999999999, 'dlp_is_unique_count': 'false', 'dlp_parent_id': 9999999999, 'dlp_profile': 'DLP Ogmasec Amber', 'dlp_rule': 'Ogmasec Amber rule', 'dlp_rule_count': 1, 'dlp_rule_severity': 'Low', 'dst_country': 'US', 'dst_latitude': 34.035, 'dst_location': 'Colbert', 'dst_longitude': -83.2191, 'dst_region': 'Georgia', 'dst_timezone': 'America/New_York', 'dst_zipcode': '30628', 'dstip': '142.250.179.97', 'file_lang': 'Unknown', 'file_size': 12773, 'file_type': 'application/pdf', 'from_user': 'mathieu.guerin@ogmasec.fr', 'hostname': 'PC', 'incident_id': 899404351323158813, 'instance_id': 'ogmasec.fr', 'managed_app': 'no', 'managementID': '', 'md5': '5b8b9381043d8576a8f88bbc9f2b0999', 'object': 'amber DLP.docx.pdf', 'object_id': '1XWEGhZHEizUjHzv4dpdRJSNZr-wpRPJk', 'object_type': 'File', 'organization_unit': '', 'os': 'Windows 11', 'os_version': 'Windows 11', 'page': 'drive.usercontent.google.com', 'page_site': 'Google Drive', 'policy': 'block AMBER files', 'policy_id': '7B5C019A7148AA500AB5E1426EB7EB19 2023-09-15 14:16:24.904568', 'protocol': 'HTTPS/1.1', 'request_id': 2667823107070723584, 'sanctioned_instance': 'Yes', 'scan_type': '', 'severity': 'unknown', 'sha256': 'b5081cf9e1bffacee320bc4b0878013ad5de2003615b8d75fefcc86637d98474', 'site': 'Google Drive', 'src_country': 'FR', 'src_latitude': 43.4951, 'src_location': 'Bayonne', 'src_longitude': -1.4739, 'src_region': 'Nouvelle-Aquitaine', 'src_time': 'Mon Sep 18 14:53:16 2023', 'src_timezone': 'Europe/Paris', 'src_zipcode': '64100', 'srcip': '91.160.73.239', 'timestamp': 1695041643, 'title': 'amber DLP.docx.pdf', 'traffic_type': 'CloudApp', 'transaction_id': 899404351323158813, 'true_obj_category': 'Word Processor', 'true_obj_type': 'Adobe Portable Document Format (PDF)', 'true_type_id': 230, 'tss_mode': 'inline', 'type': 'nspolicy', 'ur_normalized': 'mguerin@netskope.com', 'url': 'drive.usercontent.google.com/download', 'user': 'mguerin@netskope.com', 'userip': '192.168.1.59', 'userkey': 'mguerin@netskope.com', 'classification_name': '', 'message_id': '', 'universal_connector': '', 'dst_geoip_src': 0, 'user_id': '', 'external_collaborator_count': 0, 'file_path': '', 'userPrincipalName': '', 'src_geoip_src': 0, 'group': '', 'web_universal_connector': '', 'file_category': '', 'channel': '', 'sAMAccountName': '', 'dlp_fingerprint_score': 0, 'retro_scan_name': '', 'dlp_fingerprint_match': '', 'true_filetype': '', 'message_size': 0, 'total_collaborator_count': 0, 'dlp_unique_count': 0, 'instance': '', 'to_storage': '', 'dlp_rule_score': 0, 'data_type': '', 'owner': '', 'from_storage': '', 'app_activity': '', 'violating_user': '', 'file_password_protected': '', 'dynamic_classification': '', 'parent_id': '', 'dlp_fingerprint_classification': '', 'bcc': '', 'outer_doc_type': 0, 'mime_type': '', 'owner_pdl': '', 'smtp_to': [], 'userCountry': '', 'exposure': '', 'shared_with': '', 'mail': '', 'shared_domains': '', 'file_cls_encrypted': False, 'manager': '', 'dlp_mail_parent_id': '', 'to_user': '', 'suppression_key': '', 'orignal_file_path': '', 'local_sha256': '', 'violating_user_type': '', 'act_user': '', 'sub_type': '', 'modified': 0, 'referer': '', 'collaborated': '', 'displayName': ''}], 'wait_time': 1, 'timestamp_hwm': 1695041645}

        """
        OFFLINE
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
        """
        #return data
        return data
    


    '''
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
    '''
    

  
    selected_fields = []
    """
    OFFLINE
    while True:
        response = _getData(operation)

        if 'result' in response and isinstance(response['result'], list) and len(response['result']) == 0:
            print("No more data...")
            logger.info("No more data...")
            break
        #selected_fields,wait= _extractFields(response,selected_fields)
        operation = "next"
        #logger.info(f"Waiting {wait+1} seconds for API rate limiting...")
        #time.sleep(wait+1)
    """
    
    ###OFFLINE
    response = _getData(operation)
    dlp_incident_ids = []
    #dlp_incident_ids = [item['dlp_incident_id'] for item in response['result'] if 'dlp_incident_id' in item]
    #alert_name = [item['alert_name'] for item in response['result'] if 'alert_name' in item]
    
    for item in response['result']:
        if 'dlp_incident_id' in item:
            dlp_incident_ids.append(item['dlp_incident_id'])


    print(dlp_incident_ids)
    #print(alert_name)

    num_rows = len(selected_fields)
    print(selected_fields)
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
  
    '''