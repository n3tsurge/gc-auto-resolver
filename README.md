# Guardicore Incident Auto Resolver

This tool automatically resolves Guardicore Incidents in the Centra UI based on a set of rules defined in `config.yml`

![Example](example.png)

## Quickstart

### Manual Start

1. Clone the repository `git clone git@github.com:n3tsurge/gc-auto-resolver.git`
2. Change directories to `cd gc-auto-resolver`
3. Make sure `pipenv` is installed using `pip install pipenv`
4. Run `pipenv install`
5. Rename `config.yml.sample` to `config.yml`
6. Add your Guardicore management url in `config.yml`
7. Add your API accounts credentials in `config.yml`
8. Define your rules
9. Define your threat feeds
10. Run the tool using `pipenv run python gc-auto-resolver.py`

### Docker

1. Download the repository
2. Modify your `config.yml` file 
3. Build the image `docker build -t gc-auto-resolver ./`
4. Run the image using `docker-compose up -d`

```bash
git clone git@github.com:n3tsurge/gc-auto-resolver.git
cd gc-auto-resolver
docker build -t gc-auto-resolver ./
docker-compose up -d
```

## Feature Checklist

- [x] Dockerized version
- [x] Enrich and resolve incidents using external threat lists
- [x] Add IPs to a `override block` rule in Guardicore
- [ ] Check to see if an IP has any records in a DNSBL
- [ ] Enrich and resolve incidents using platforms like VirusTotal, Greynoise, etc.
- [ ] Add malicious IPs to custom threat list file for use by Palo Alto EDL (external dynamic list)
- [ ] Add support for OpenCTI
- [ ] Add support for MISP
- [ ] Add support for Memcached
- [ ] Add support for Elasticsearch indices
- [ ] SentinelOne Deep Visibility initiating process threat enrichment
- [ ] Country blocking

## Future State

- Ability to write complex rules like `opencti_hit > 1 AND threat_list_matches > 3`
- Ability to write per action rules e.g. only block if `X & Y & Z` but resolve of `A|B`

## Caching

By default the tool will cache HTTP requests for HTTP based lists to limit the number of times a list needs to be fetched.  This is controlled in `config.yml` in this section:

```yaml
caching:
  enabled: true
  backend: sqlite
  expiration: 43200 # 12 hours
```

## Defining Threat Feeds

```yaml
feeds:
  alienvault:
    name: Alienvault
    url: http://reputation.alienvault.com/reputation.data
    format: ip|cidr|dns
    geodata: true|false
    disabled: true|false
    type: list|dns
```

## Defining Rules

There are several types of resolution rules you can create

### Intel Sources

- **lists** - Looks to DNSBL and HTTP based lists for threat intelligence
- **virustotal** - Looks to  VirusTotal for threat intelligence on an IP
- **greynoise** - Looks to Greynoise for threat intelligence on an IP
- **sentinelone** - Runs a SentinelOne Deep Visibility query for the process initiating the traffic and checks threat information about the process
- **opencti** - Looks to an OpenCTI for threat intelligence
- **misp** - Looks to the MISP API for threat intelligence
- **memcached** - Looks to a specified memcached namespace for threat intelligence
- **elasticsearch** - Look to a threat list stored in an elasticsearch index

### Actions

- **block** - Adds a block rule in Guardicore for the IP in question (can be `SOURCE` or `DESTINATION` or `BOTH`)
- **resolve** - Adds the `Acknowledged` tag to the incident in Guardicore
- **tag** - Adds tags to the Incident in Guardicore
- **thehive** - Creates an incident in the TheHive
- **paloedl** - Creates an entry for Palo Alto External Dynamic Lists, lists can be called by having the Palo Alto point top `http://[container-ip]:[port]/edl?list_name=[specify_list]`

#### Sample Rule

The rule will look towards external threat lists and DNS lists to determine if the threat is malicious or not. When the number of threat lists meets or exceeds `minimum_hits` the Incident will be tagged with the lists the IP addres appears on and the `Auto-Acknowledged` tag.

#### Example

```yaml
Passive Detection:
  tags:
    - Blacklisted IP Address # The tags that an incident should have when polling Centra incidents
  resolution_tags:
    - Auto-Acknowledged # The tags to assign to the incident at resolution time
  minimum_hits: 2
  dont_resolve: false # Set to true if you only want to tag an incident
  intel_source: 
    - lists
  actions:
    - block
      rule_set: "Automatic Blacklisted IP Blocking"
      direction: BOTH
    - resolve
    - tag
```

### Engines

When using `virustotal`, `sentinelone`, `greynoise`, `opencti`, or `misp` you can configure them in the `engines` section of `config.yml`

> :warning: **Work in Progress** This feature is not yet implemented

#### Example Configuration

```yaml
engines:
  virustotal:
    enabled: false
    api_key: ""
  greynoise:
    enabled: false
    api_key: ""
  sentinelone:
    enabled: false
    api_key: ""
    management_url: ""
```

## Warranty & Support

I am not responsible if you break your system with this script.  Usage is up to your own risk appetite.
