import os
import requests
import json

url = "https://www.virustotal.com/api/v3/files/upload_url"

headers = {
    "accept": "application/json",
    "x-apikey": os.environ.get("VT_API")  
}

response = (requests.get(url, headers=headers)).json()

files = { "file": ("teste", open("/home/jose/Downloads/com.spike.old.apk", "rb"), "application/vnd.android.package-archive") }

response2 = (requests.post(response["data"],files=files,headers=headers)).json()

print(response2['data']['links']['self'])

print("="*100)

response3 = (requests.get(response2['data']['links']['self'],headers=headers)).json()

with open('response3','w') as f:
    f.write(str(response3))

print("="*100)

response4 = (requests.get(response3['data']['links']['item'],headers=headers)).json()

with open('response4','w') as f:
    f.write(str(response4))