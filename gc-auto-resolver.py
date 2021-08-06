import json
import yaml
import requests
import logging
import requests_cache
import time
from datetime import datetime, timedelta
from argparse import ArgumentParser
from pyaml_env import parse_config
from threat_feeds.feed import Feed


def load_config(path="config.yml"):
    """
    Loads the configuration file for the application
    and returns a configuration object for consumption in
    other areas
    """
    config_error = False
    config = parse_config(path)

    return config


def load_feeds(feed_configs):
    """
    Initiates a Feed object for each threat feed configured
    """
    feeds = [Feed(feed_configs[f]) for f in feed_configs if feed_configs[f]['disabled'] == False]
    return feeds


def gc_authenticate(management_url, username, password):
    """
    Authenticates to the Guardicore API
    """

    s = requests.Session()

    auth_body = {
        "username": username,
        "password": password
    }

    headers = {
        "Content-Type": "application/json"
    }

    access_token = None

    response = s.post(f"https://{management_url}/api/v3.0/authenticate", data=json.dumps(auth_body), headers=headers)
    if response.status_code == 200:
        access_token = response.json()["access_token"]

    return access_token

def gc_get_incidents(management_url, access_token, tags=[]):
    """
    Fetches a list of un-acknowledged incidents from the last 24 hours
    """
    tag_list = ",".join(tags)
    from_time = int((datetime.now() - timedelta(hours=24)).timestamp()) * 1000
    to_time = int(datetime.now().timestamp()) * 1000

    with requests.Session() as s:
        s.headers.update({
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}"
        })
        url = f"https://{management_url}/api/v3.0/incidents?tag={tag_list}&tag__not=Acknowledged&from_time={from_time}&to_time={to_time}&limit=500"
        response = s.get(url)
        if response.status_code == 200:
            data = response.json()
    return data['objects']


def gc_tag_incident(management_url, access_token, incident_id, tags=[]):
    """
    Tags an incident with information and Acknowledges it
    identifying that it was resolved for certain reasons
    automatically
    """

    """ From Devtools response - Undocumented API endpoint
    POST
    https://cus-2782.cloud.guardicore.com/api/v3.0/incidents/acknowledge
    {"ids":["e9fde08e-c52a-469e-971d-ab15f8ec672f"],"negate_args":null}
    """

    """ From Devtools response - Undocumented API endpoint
    POST
    https://cus-2782.cloud.guardicore.com/api/v3.0/incidents/tag
    {"action":"add","tag_name":"Test","negate_args":null,"ids":["91d5531d-5915-477a-ae95-1af6981df625"]}
    """

    with requests.Session() as s:
        s.headers.update({
            "Content-Type": "application/json",
            "Authorization": f"Bearer {access_token}"
        })

        # Assign all the tags
        for tag in tags:
            data = {
                "action": "add",
                "tag_name": tag,
                "negate_args": None,
                "ids": [incident_id]
            }
            s.post(f"https://{management_url}/api/v3.0/incidents/tag", data=json.dumps(data))

        # Acknowledge the incident
        data = {
            "ids": [incident_id],
            "negate_args": None
        }
        s.post(f"https://{management_url}/api/v3.0/incidents/acknowledge", data=json.dumps(data))

    return


def vt_lookup(ip):
    """
    Checks the VirusTotal API for threat intel on a given IP address
    """
    raise NotImplemented

def gn_lookup(ip):
    """
    Checks the Greynoise API for threat intel on a given IP address
    """
    raise NotImplemented


def enrich_incident(incident, minimum_hits, feeds=[]):
    source = incident["source_asset"]
    destination = incident["destination_asset"]

    ip = None
    total_feeds = len(feeds)
    found_in = 0
    feed_names = []

    if destination['is_inner'] == False:
        ip = destination['ip']

    if source['is_inner'] == False:
        ip = source['ip']

    if ip:
        for feed in feeds:
            found =  feed.check_ip(ip)
            if found:
                found_in += 1
                feed_names += [f"External threat list: {feed.name}"]
    logging.info(f"{ip} found in {found_in}/{total_feeds} threat feeds.")
    
    # If the rule stipulates a certain number of hits for threat feeds and we meet or exceed 
    # that threshold, automatically resolve the alarm
    if found_in >= minimum_hits:
        return True, feed_names
    return False, feed_names


if __name__ == "__main__":

    # Set the logging format
    logging.basicConfig(
        format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)

    parser = ArgumentParser()
    parser.add_argument('--config', help="The path to the configuration file", default="config.yml", required=False)

    args = parser.parse_args()

    config = load_config(path=args.config)

    # Hook requests with the cache
    if config['caching']['enabled']:
        logging.info("Enabling caching for Requests with a {} second(s) expiration period".format(config['caching']['expiration']))
        requests_cache.install_cache('gc-auto-resolve', backend=config['caching']['backend'], expire_after=config['caching']['expiration'])

    logging.info("Authenticating to Guardicore")
    access_token = gc_authenticate(**config['guardicore'])

    feeds = load_feeds(config['feeds'])
    
    while True:
        for rule in config['rules']:
            rule_config = config['rules'][rule]
            logging.info(f"Running rule \"{rule}\"")

            incidents = gc_get_incidents(config['guardicore']['management_url'], access_token, tags=rule_config['tags'])
            if len(incidents) > 0:
                logging.info("Processing {} incidents".format(len(incidents)))
            
                for incident in incidents:

                    threshold_exceeded = False

                    if "threat_enrich" in rule_config['type']:
                        threshold_exceeded, feed_names = enrich_incident(incident, rule_config['minimum_hits'], feeds=feeds)

                    if "threat_engine" in rule_config['type']:
                        logging.warning("Threat Engines not yet implemented.")

                    if threshold_exceeded:
                        gc_tag_incident(config['guardicore']['management_url'], access_token, incident['id'], tags=feed_names+rule_config['resolution_tags'])

        sleep_interval = config['global']['interval']
        logging.info(f"Sleeping for {sleep_interval} seconds")
        time.sleep(sleep_interval)
