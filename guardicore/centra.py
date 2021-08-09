import json
import requests
from datetime import datetime, timedelta

class CentraAPI(object):

    def __init__(self, management_url=""):
        """
        Initializes an API object that is used
        to make consistent calls to the Guardicore Centra API
        """

        self.management_url = management_url
        self.session = requests.Session()

        self.session.headers.update({
            'Content-Type': 'application/json'
        })

    def authenticate(self, username, password):
        """
        Authenticates to the Guardicore Centra API and 
        gets back an access_token
        """

        auth_body = {
            "username": username,
            "password": password
        }

        response = self.session.post(f"https://{self.management_url}/api/v3.0/authenticate", data=json.dumps(auth_body))
        if response.status_code == 200:
            data = response.json()
            self.session.headers.update({
                "Authorization": f"Bearer {data['access_token']}"
            })
    
    def block_ip(self, ip, rule_set, direction):
        """
        Adds an IP address to a policy rule to block
        traffic to and/or from the IP in question
        """

        if direction not in ["DESTINATION","SOURCE","BOTH"]:
            raise ValueError("direction must either be DESTINATION, SOURCE or BOTH")

        if direction in ["DESTINATION", "BOTH"]:
            data = {
                "direction": "DESTINATION",
                "reputation_type": "top_ips",
                "ruleset_name": rule_set + " | Outbound",
                "value": ip
            }
            self.session.post(f"https://{self.management_url}/api/v3.0/widgets/malicious-reputation-block", data=json.dumps(data))
            
        if direction in ["SOURCE", "BOTH"]:
            data = {
                "direction": "SOURCE",
                "reputation_type": "top_ips",
                "ruleset_name": rule_set + " | Inbound",
                "value": ip
            }
            self.session.post(f"https://{self.management_url}/api/v3.0/widgets/malicious-reputation-block", data=json.dumps(data))


    def get_incidents(self, tags=[], tag__not=["Acknowledged"], limit=500, from_hours=24):
        """
        Fetches a list of incidents from Centra UI based on
        a set of criteria
        """

        tag_list = ",".join(tags)
        tag__not = ",".join(tag__not)
        from_time = int((datetime.now() - timedelta(hours=from_hours)).timestamp()) * 1000
        to_time = int(datetime.now().timestamp()) * 1000

        url = f"https://{self.management_url}/api/v3.0/incidents?tag={tag_list}&tag__not={tag__not}&from_time={from_time}&to_time={to_time}&limit={limit}"
        response = self.session.get(url)
        if response.status_code == 200:
            data = response.json()
            return data['objects']
        else:
            return []

    def tag_incident(self, id, tags):
        """
        Tags an incident with user and system defined
        tags so analysts can triage a threat more 
        readily or look back as to why a threat was triaged
        the way it was 
        """

        # Assign all the tags
        for tag in tags:
            data = {
                "action": "add",
                "tag_name": tag,
                "negate_args": None,
                "ids": [id]
            }
            self.session.post(f"https://{self.management_url}/api/v3.0/incidents/tag", data=json.dumps(data))

    def acknowledge_incident(self, ids=[]):
        """
        Sets the Acknowledged tag on any incidents
        present in the ids variable
        """

        # Make sure this is a list
        if not isinstance(ids, list):
            raise TypeError("ids should be a list")

        data = {
            "ids": ids,
            "negate_args": None
        }
        self.session.post(f"https://{self.management_url}/api/v3.0/incidents/acknowledge", data=json.dumps(data))

    def get_inner(self, destination, source):
        """
        Returns the IP that is part of an incident that is actually
        the bad indicator of the traffic
        """
        if destination['is_inner'] == False:
            return destination['ip']
        else:
            return source['ip']