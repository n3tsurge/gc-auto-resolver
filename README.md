# Guardicore Incident Auto Resolver

This tool automatically resolves Guardicore Incidents in the Centra UI based on a set of rules defined in `config.yml`

## Getting started

1. Rename `config.yml.sample` to `config.yml`
2. Add your Guardicore management url
3. Add your API accounts credentials
4. Define your rules
5. Define your threat feeds
6. Run the tool

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

### Threat Enrich

The `threat_enrich` rule will look towards external threat lists and DNS lists to determine if the threat is malicious or not. When the number of threat lists meets or exceeds `minimum_hits` the Incident will be tagged with the lists the IP addres appears on and the `Auto-Acknowledged` tag.

#### Example

```yaml
Passive Detection:
  tags:
    - Blacklisted IP Address
  resolution_tags:
    - Auto-Acknowledged
  minimum_hits: 2
  dont_resolve: true|false  # Set to true if you want to enrich the incident and have an analyst manually review in the Centra UI
  type: threat_enrich
```

### Engine

The `threat_engine` rule will look towards pay-to-win services like VirusTotal, GreyNoise, etc. to determine if a threat is malicious or not.

!!! note "Work in Progress"
    NOT IMPLEMENTED YET

#### Example Configuration

```yaml
engines:
  virustotal:
    enabled: false
    api_key: ""
  greynoise:
    enabled: false
    api_key: ""
```


