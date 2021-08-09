import dns.resolver
import requests
import re
import requests_cache
import logging
from requests import exceptions as rexp
from netaddr import IPSet, IPNetwork, IPAddress


class Feed(object):
    '''
    Creates a Feed object that allows for easier interaction with each
    individual blacklist feed
    '''
    def __init__(self, data):
        '''
        Initializes the Feed object
        :param data: A JSON formatted string that builds the object
        '''
        self.__dict__.update(data)

    def check_ip(self, ip, options=None, *args, **kwargs):
        if self.type == "list":
            return self.check_ip_list(ip, options, *args, **kwargs)
        elif self.type == "dns":
            return self.check_ip_dns(ip, options, *args, **kwargs)


    def check_ip_list(self, ip, options=None, *args, **kwargs):
        '''
        Checks a given IP against the blacklist
        :param self:
        :param ip: The IP address that we want to look for
        :param options: The OptParse options from the main() function
        :return Found|No Result:
        '''

        session = requests.Session()

        # Skip the feed if it is disabled in config
        if hasattr(self, "disabled") and self.disabled:
            return "Skipped - Disabled"

        # If the user supplied a proxy, set the proxy information for requests
        if hasattr(options,'proxy') and options.proxy:
            session.proxies = {"http": options.proxy, "https": options.proxy}
            session.auth = HTTPProxyAuth(options.proxy_user, options.proxy_pass)

        # Try to pull down the data from the feed URL
        try:
            result = session.get(self.url)
            if not result.from_cache:
                logging.warning("Not from cache.")
            if result.status_code == 200:

                # If the threat feed is in CIDR notation, pull all the listed subnets
                # then see if the IP is a member of each one, if we find it stop checking
                # If NOT CIDR notation, do the normal IP check
                if self.format == "cidr":
                    for cidr in [IPNetwork(cidr) for cidr in re.findall("((?:\d{1,3}\.){3}\d{1,3}(?:/\d\d?))", result.text)]:
                        if IPAddress(ip) in cidr:
                            return "Found"
                    return "No Result"
                else:
                    matches = re.findall(ip, result.text)
                if matches:
                    return True
                    #return "Found"
                else:
                    return False
                    #return "No Result"
            else:
                cprint("[!] There was an issue attemping to connect to: {url}".format(url=self.url), RED)
                return False
        except rexp.ConnectionError as e:
            cprint("[!] There was an issue attemping to connect to: {url}".format(url=self.url), RED)
            return False

    def check_ip_dns(self, ip, options=None, *args, **kwargs):
        '''
        Checks a given IP against a DNSBL (DNS Blacklist)
        :param self:
        :param ip:  The IP we are looking for
        :param options:  The OptParse options from the main() function
        :return Found|No Result|Timeout|No Answer
        '''

        try:
        # Build our resolver
            r = dns.resolver.Resolver()

        # Create a reverse DNS query for the IP in question
            query = '.'.join(reversed(str(ip).split("."))) + "." + self.url
            r.timeout = 5
            r.lifetime = 5

            # Check for any A and TXT records matching the reverse record
            answers = r.query(query, "A")
            answers_txt = r.query(query, "TXT")

            # Return a Found response if we have anythin in either list
            if answers or answers_txt:
                return "Found"

        except dns.resolver.NXDOMAIN:
            return "Not Found"
        except dns.resolver.Timeout:
            return "Timeout"
        except dns.resolver.NoAnswer:
            return "No Answer"
        except dns.resolver.NoNameservers:
            return "No Name Servers"
