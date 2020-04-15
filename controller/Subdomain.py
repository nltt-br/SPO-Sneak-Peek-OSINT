__Author__ = "Victor de Queiroz"
# -*- coding:UTF-8 -*-
'''
Class for APIv2 Treat Crowd
http://www.threatcrowd.org

This Class return subdomains, emails, ip and hash/file

'''

import requests, json

class Consumer_ThreatCrowd_API():

    def get_subdomains(self, domain):
        # get info for domain on threat crowd
        response = requests.get("http://www.threatcrowd.org/searchApi/v2/domain/report/", params={"domain": domain})

        domain_info = json.loads(response.text)

        if domain_info['response_code'] == '1':
            return domain_info['subdomains']
        else:
            return ""

    def get_email(self, email):
        # get info for email on threat crowd
        response = requests.get("https://www.threatcrowd.org/searchApi/v2/email/report/", params={"email": email})

        email_info = json.loads(response.text)

        if email_info['response_code'] == '1':
            return email_info['domains']
        else:
            return ""

    def get_ip(self, ip):
        # get info for ip on threat crowd
        response = requests.get("https://www.threatcrowd.org/searchApi/v2/ip/report/", params={"ip": ip})

        ip_info = json.loads(response.text)

        if ip_info['response_code'] == '1':
            return ip_info['last_resolved']
        else:
            return ""

    def get_resource(self, resource):
        # get info for hash file on threat crowd
        response = requests.get("https://www.threatcrowd.org/searchApi/v2/file/report/", params={"resource": resource})

        resource_info = json.loads(response.text)

        if resource['response_code'] == '1':
            return resource['scans']
        else:
            return ""
