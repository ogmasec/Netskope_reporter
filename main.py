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
    


    def getData(self,start,now):
        logger.info(f"start date :{datetime.fromtimestamp(start)} stop date: {datetime.fromtimestamp(now)}")
        operation = start
        last = 0
        pause = 5
        All_DLP_Incidents = list()

        timeout = 0
        while last < now or timeout >= 45:
            params_dlp = {"operation": operation,"index":"PYSCRIPT_TAM_"+str(now)}
            dlp_incidents_list = self.get_dlp_incident(params_dlp,wait=pause)
            
            if last == dlp_incidents_list.get('timestamp_hwm'):
                timeout+=1
                logger.info(f'Timeout reached {timeout}...')
            else:
                timeout = 0
                last = dlp_incidents_list.get('timestamp_hwm')
            
            pause = dlp_incidents_list.get('wait_time')
            print(f"{last} :{now}")
            if 'result' in dlp_incidents_list and isinstance(dlp_incidents_list['result'], list) and len(dlp_incidents_list['result']) != 0:
                print(f"resultat : {dlp_incidents_list['result']}")
                All_DLP_Incidents.append(dlp_incidents_list['result'])
            if operation != "next": ## change "operation" from "head" to next
                operation = "next"
                logger.info(f"Operation is now 'Next'...")
        logger.info(f"Duration = {int(time.time())-now} secondes")
        return All_DLP_Incidents

    def filterData(self,headers):
        # Créer un dictionnaire vide
        dict_result = {key: [] for key in headers}

        # Remplir le dictionnaire
        for line in All_DLP_Incidents:
            for item in headers:
                value = line.get(item)
                if value is not None:
                    dict_result[item].append(value)
        return dict_result
    

# Utilisation de la classe NetskopeAPI
if __name__ == "__main__":
    
    ### Get DLP Incidents ###
    #FAR : Get args
    nskp_dlp_incidents = NetskopeAPI()
    now = int(time.time())
    start = now-864000 # -10 days
    start = 1703145656
    #today = 1702631232 ## testing from

    
    
    All_DLP_Incidents = nskp_dlp_incidents.getData(start,now)
    """
    #print(All_DLP_Incidents)
    All_DLP_Incidents = list()
    All_DLP_Incidents.append(dict({'_id': 'b534369a0cb86c26ec9c13be', 'access_method': 'Client', 'acked': 'false', 'action': 'block', 'activity': 'Download', 'alert': 'yes', 'alert_name': 'block AMBER files', 'alert_type': 'DLP', 'app': 'Google Drive', 'app_session_id': 1353211701451090249, 'appcategory': 'Cloud Storage', 'appsuite': 'Google App', 'browser': 'Chrome', 'browser_session_id': 8749970105231557795, 'browser_version': '120.0.0.0', 'category': 'Cloud Storage', 'ccl': 'high', 'connection_id': 5319692086432804219, 'device': 'Mac Device', 'device_classification': 'managed', 'dlp_file': 'amber DLP.docx.pdf', 'dlp_incident_id': 7030386564327161514, 'dlp_is_unique_count': 'false', 'dlp_parent_id': 7030386564327161514, 'dlp_profile': 'DLP Ogmasec Amber', 'dlp_rule': 'Ogmasec Amber rule', 'dlp_rule_count': 1, 'dlp_rule_severity': 'Low', 'dst_country': 'US', 'dst_latitude': 37.4043, 'dst_location': 'Mountain View', 'dst_longitude': -122.0748, 'dst_region': 'California', 'dst_timezone': 'America/Los_Angeles', 'dst_zipcode': '94043', 'dstip': '216.58.205.193', 'file_lang': 'Unknown', 'file_size': 12773, 'file_type': 'application/pdf', 'from_user': 'mathieu.guerin@ogmasec.fr', 'hostname': 'JXYG32P4VY', 'incident_id': 8471058460444493330, 'instance_id': 'ogmasec.fr', 'managed_app': 'no', 'md5': '03b9d9196a14eb28ff26277024da888f', 'object': 'amber DLP.docx.pdf', 'object_type': 'File', 'organization_unit': '', 'os': 'Mac OS', 'os_version': 'Mac OS', 'outer_doc_type': 230, 'page': 'docs.google.com', 'page_site': 'Google Drive', 'policy': 'block AMBER files', 'policy_id': '5D2396EF48507A58FEB628DF9DDF5FD2 2023-10-25 07:47:31.125849', 'protocol': 'HTTPS/1.1', 'referer': 'https://docs.google.com/', 'request_id': 2731520722068454144, 'sanctioned_instance': 'Yes', 'scan_type': '', 'severity': 'unknown', 'sha256': 'c27b0b52d5892d9e34eb1526ec81df27c3ce78946f81b4ae89eff3a5b633f811', 'site': 'Google Drive', 'src_country': 'FR', 'src_latitude': 43.4951, 'src_location': 'Bayonne', 'src_longitude': -1.4739, 'src_region': 'Nouvelle-Aquitaine', 'src_time': 'Fri Dec 15 11:09:00 2023', 'src_timezone': 'Europe/Paris', 'src_zipcode': '64100', 'srcip': '91.160.73.239', 'timestamp': 1702634990, 'title': 'amber DLP.docx.pdf', 'traffic_type': 'CloudApp', 'transaction_id': 8471058460444493330, 'true_obj_category': 'Word Processor', 'true_obj_type': 'Adobe Portable Document Format (PDF)', 'true_type_id': 230, 'tss_mode': 'inline', 'type': 'nspolicy', 'ur_normalized': 'mguerin@netskope.com', 'url': 'doc-04-18-docstext.googleusercontent.com/export/ushh1qhlp1kspp7417i74qq1rk/q0skannrp1g4fplf95ndhoe2hc/1702634985000/115644520798372391057/115644520798372391057/1Zygg_Ai3LweBfpCvBRRgx5vGIQbERqs8', 'user': 'mguerin@netskope.com', 'userip': '192.168.1.90', 'userkey': 'mguerin@netskope.com', 'dlp_fingerprint_match': '', 'act_user': '', 'object_id': '', 'external_collaborator_count': 0, 'owner': '', 'dlp_fingerprint_score': 0, 'violating_user': '', 'group': '', 'local_sha256': '', 'retro_scan_name': '', 'shared_with': '', 'to_user': '', 'dynamic_classification': '', 'sub_type': '', 'modified': 0, 'violating_user_type': '', 'mime_type': '', 'instance': '', 'file_category': '', 'sAMAccountName': '', 'user_id': '', 'message_size': 0, 'dst_geoip_src': 0, 'from_storage': '', 'dlp_unique_count': 0, 'orignal_file_path': '', 'universal_connector': '', 'userPrincipalName': '', 'true_filetype': '', 'collaborated': '', 'owner_pdl': '', 'src_geoip_src': 0, 'dlp_fingerprint_classification': '', 'file_password_protected': '', 'dlp_rule_score': 0, 'web_universal_connector': '', 'mail': '', 'file_path': '', 'exposure': '', 'classification_name': '', 'manager': '', 'parent_id': '', 'displayName': '', 'bcc': '', 'managementID': '', 'dlp_mail_parent_id': '', 'app_activity': '', 'suppression_key': '', 'to_storage': '', 'data_type': '', 'total_collaborator_count': 0, 'message_id': '', 'file_cls_encrypted': False, 'smtp_to': [], 'userCountry': '', 'channel': '', 'shared_domains': ''}))
    All_DLP_Incidents.append(dict({'_id': 'b534369a0cb86c26ec9c13be', 'access_method': 'Client', 'acked': 'false', 'action': 'accept', 'activity': 'Download', 'alert': 'yes', 'alert_name': 'block AMBER files', 'alert_type': 'DLP', 'app': 'Google Drive', 'app_session_id': 1353211701451090249, 'appcategory': 'Cloud Storage', 'appsuite': 'Google App', 'browser': 'Chrome', 'browser_session_id': 8749970105231557795, 'browser_version': '120.0.0.0', 'category': 'Cloud Storage', 'ccl': 'high', 'connection_id': 5319692086432804219, 'device': 'Mac Device', 'device_classification': 'managed', 'dlp_file': 'amber DLP.docx.pdf', 'dlp_incident_id': 7030386564327161515, 'dlp_is_unique_count': 'false', 'dlp_parent_id': 7030386564327161514, 'dlp_profile': 'DLP Ogmasec Amber', 'dlp_rule': 'Ogmasec Amber rule', 'dlp_rule_count': 1, 'dlp_rule_severity': 'Low', 'dst_country': 'US', 'dst_latitude': 37.4043, 'dst_location': 'Mountain View', 'dst_longitude': -122.0748, 'dst_region': 'California', 'dst_timezone': 'America/Los_Angeles', 'dst_zipcode': '94043', 'dstip': '216.58.205.193', 'file_lang': 'Unknown', 'file_size': 12773, 'file_type': 'application/pdf', 'from_user': 'mathieu.guerin@ogmasec.fr', 'hostname': 'JXYG32P4VY', 'incident_id': 8471058460444493330, 'instance_id': 'ogmasec.fr', 'managed_app': 'no', 'md5': '03b9d9196a14eb28ff26277024da888f', 'object': 'amber DLP.docx.pdf', 'object_type': 'File', 'organization_unit': '', 'os': 'Mac OS', 'os_version': 'Mac OS', 'outer_doc_type': 230, 'page': 'docs.google.com', 'page_site': 'Google Drive', 'policy': 'block AMBER files', 'policy_id': '5D2396EF48507A58FEB628DF9DDF5FD2 2023-10-25 07:47:31.125849', 'protocol': 'HTTPS/1.1', 'referer': 'https://docs.google.com/', 'request_id': 2731520722068454144, 'sanctioned_instance': 'Yes', 'scan_type': '', 'severity': 'unknown', 'sha256': 'c27b0b52d5892d9e34eb1526ec81df27c3ce78946f81b4ae89eff3a5b633f811', 'site': 'Google Drive', 'src_country': 'FR', 'src_latitude': 43.4951, 'src_location': 'Bayonne', 'src_longitude': -1.4739, 'src_region': 'Nouvelle-Aquitaine', 'src_time': 'Fri Dec 15 11:09:00 2023', 'src_timezone': 'Europe/Paris', 'src_zipcode': '64100', 'srcip': '91.160.73.239', 'timestamp': 1702634990, 'title': 'amber DLP.docx.pdf', 'traffic_type': 'CloudApp', 'transaction_id': 8471058460444493330, 'true_obj_category': 'Word Processor', 'true_obj_type': 'Adobe Portable Document Format (PDF)', 'true_type_id': 230, 'tss_mode': 'inline', 'type': 'nspolicy', 'ur_normalized': 'mguerin@netskope.com', 'url': 'doc-04-18-docstext.googleusercontent.com/export/ushh1qhlp1kspp7417i74qq1rk/q0skannrp1g4fplf95ndhoe2hc/1702634985000/115644520798372391057/115644520798372391057/1Zygg_Ai3LweBfpCvBRRgx5vGIQbERqs8', 'user': 'mguerin@netskope.com', 'userip': '192.168.1.90', 'userkey': 'mguerin@netskope.com', 'dlp_fingerprint_match': '', 'act_user': '', 'object_id': '', 'external_collaborator_count': 0, 'owner': '', 'dlp_fingerprint_score': 0, 'violating_user': '', 'group': '', 'local_sha256': '', 'retro_scan_name': '', 'shared_with': '', 'to_user': '', 'dynamic_classification': '', 'sub_type': '', 'modified': 0, 'violating_user_type': '', 'mime_type': '', 'instance': '', 'file_category': '', 'sAMAccountName': '', 'user_id': '', 'message_size': 0, 'dst_geoip_src': 0, 'from_storage': '', 'dlp_unique_count': 0, 'orignal_file_path': '', 'universal_connector': '', 'userPrincipalName': '', 'true_filetype': '', 'collaborated': '', 'owner_pdl': '', 'src_geoip_src': 0, 'dlp_fingerprint_classification': '', 'file_password_protected': '', 'dlp_rule_score': 0, 'web_universal_connector': '', 'mail': '', 'file_path': '', 'exposure': '', 'classification_name': '', 'manager': '', 'parent_id': '', 'displayName': '', 'bcc': '', 'managementID': '', 'dlp_mail_parent_id': '', 'app_activity': '', 'suppression_key': '', 'to_storage': '', 'data_type': '', 'total_collaborator_count': 0, 'message_id': '', 'file_cls_encrypted': False, 'smtp_to': [], 'userCountry': '', 'channel': '', 'shared_domains': ''}))
    
    headers = ['incident_id','action','activity']
    print(nskp_dlp_incidents.filterData(headers))
    
    # Transform json input to python objects
    input_dict = json.loads(All_DLP_Incidents)

    # Filter python objects with list comprehensions
    output_dict = [x for x in input_dict if x['type'] == '1']

    # Transform python object back into json
    output_json = json.dumps(output_dict)

    # Show json
    print(output_json)

    
    fichier = open("data.txt", "x")
    fichier.write(str(All_DLP_Incidents))
    print(fichier.read())
    fichier.close()
    """
