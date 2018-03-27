#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# __author__ someone


#pt-config setup <your-username> <your-api-key>

#https://github.com/passivetotal/python_api
#pip install passivetotal==1.0.23

"""
获取子域名+ ip

选取ip段  筛选真实ip


"""
from passivetotal.libs.enrichment import EnrichmentRequest

username = "jax777@bxbsec.com"
api_key = "115ccf99af795b031ec1f9760e2751f5b86a9fa2df2c86081c63253d8723aaa8"

def passive_get_ip():
    pass

def passivs_get_subdomain(query):
    client = EnrichmentRequest(username=username,api_key=api_key)
    result = client.get_subdomains(query=query)
    _ = result['subdomains']
    subdomains = [[passive_get_ip(i)] for i in _ ]
