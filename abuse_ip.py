import requests
import json

url = 'https://api.abuseipdb.com/api/v2/check'

def check_abuse_score(ip_address):
    querystring = {
        'ipAddress': ip_address,
        'maxAgeInDays': '90'
    }

    headers = {
        'Accept': 'application/json',
        'Key': 'YOUR_API_KEY'
    }

    response = requests.request(method='GET', url=url, headers=headers, params=querystring)

    # Formatted output
    decodedResponse = json.loads(response.text)
    return decodedResponse.get('data').get('abuseConfidenceScore')

def blocktime_basedon_abusescore(score):
    if 0<=score<25:
        return 24
    elif 25<=score<50:
        return 168
    elif 50<=score<75:
        return 360
    elif 75<=score<=100:
        return 720