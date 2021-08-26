# coding: utf-8

import IP2Location, os
from requests import get


apiLink = 'https://api.ipinfodb.com/v3/ip-city?key=f5ad2b83006363b9227f48569c02468389c49dd65363884ef06598945e9d187d&ip='

ip = input("Forneça o IP: ")

finalLink = apiLink + ip

response = get(finalLink).text
print(format(response))

##database = IP2Location.IP2Location(os.path.join("data", "./IP2LOCATION-LITE-DB1.BIN"))
##rec = database.get_all("8.8.8.8")

##print(rec.country_short)
####print(rec.country_long)
##print(rec.region)
##print(rec.city)
##print(rec.latitude)
