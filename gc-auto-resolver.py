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
from guardicore.centra import CentraAPI

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


def enrich_ip(ip, minimum_hits, feeds=[]):

    total_feeds = len(feeds)
    found_in = 0
    feed_names = []

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

    feeds = load_feeds(config['feeds'])

    # Create a new CentraAPI object and authenticate to the API
    logging.info("Authenticating to Guardicore")
    centra = CentraAPI(management_url=config['guardicore']['management_url'])
    centra.authenticate(username=config['guardicore']['username'], password=config['guardicore']['password'])
    
    while True:
        for rule in config['rules']:
            rule_config = config['rules'][rule]
            logging.info(f"Running rule \"{rule}\"")

            incidents = centra.get_incidents(tags=rule_config['tags'])

            if len(incidents) > 0:
                logging.info("Processing {} incidents".format(len(incidents)))

                for incident in incidents:

                    ip = centra.get_inner(incident["source_asset"], incident["destination_asset"])
                    incident_id = incident['id']

                    threshold_exceeded = False

                    if "lists" in rule_config['intel_source']:
                        threshold_exceeded, feed_names = enrich_ip(ip, rule_config['minimum_hits'], feeds=feeds)

                    if "virustotal" in rule_config['intel_source']:
                        logging.warning("VirusTotal not yet implemented.")

                    if "greynoise" in rule_config['intel_source']:
                        logging.warning("Greynoise not yet implemented.")

                    if "sentinelone" in rule_config['intel_source']:
                        logging.warning("SentinelOne not yet implemented.")

                    if threshold_exceeded:

                        # If tag do the tagging
                        if 'tag' in rule_config['actions']:
                            tags = feed_names+rule_config['resolution_tags']
                            logging.info(f"Tagging {incident_id} with {','.join(tags)}")
                            centra.tag_incident(incident_id, tags)

                        # If resolve action acknolwedge the incident
                        if 'resolve' in rule_config['actions']:
                            logging.info(f"Setting incident {incident_id} as acknowledged.")
                            centra.acknowledge_incident(ids=[incident_id])

                        # If a block action is defined, extract the block action config and do the blocking
                        block_config = [k for k in rule_config['actions'] if isinstance(k, dict) and 'block' in k]
                        if block_config:
                            block_config = block_config[0]['block']
                            logging.info(f"Blocking {ip} in {block_config['rule_set']} for direction {block_config['direction']}")
                            centra.block_ip(ip=ip, **block_config)

        sleep_interval = config['global']['interval']
        logging.info(f"Sleeping for {sleep_interval} seconds")
        time.sleep(sleep_interval)
