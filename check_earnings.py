import requests
import json

dev_addrs = []

dev_challenges = 0
dev_night = 0

with open('developer_wallets.json', 'r') as f:
    data = json.load(f)
    for wallet in data:
        dev_addrs.append(wallet['address'])

for addr in dev_addrs:
    try:
        response = requests.get(f"https://scavenger.prod.gd.midnighttge.io/statistics/{addr}")
        response.raise_for_status()
        dev_challenges += response.json()['local']['crypto_receipts']
        dev_night += float(response.json()['local']['night_allocation'])
    except requests.exceptions.HTTPError as http_err:
        print(f"HTTP error occurred for address {addr}: {http_err}")
        continue

print("Developer Total Challenges Solved:", dev_challenges)
print("Developer NIGHT Earnings:", dev_night / 1000000)