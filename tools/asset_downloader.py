import json
import requests
import io
import os

# get directory this scripts lives in
dir_path = os.path.dirname(os.path.realpath(__file__))

# read access token:
with open(os.path.join(dir_path, 'token.txt'), 'r') as f:
  token = f.readline().rstrip()

if (token.startswith('<')):
  print('you need to replace the first line in `token.txt` with your token')
  exit(1)

#create download dir
dl_dir = os.path.join(dir_path, 'install_files')
os.makedirs(dl_dir, exist_ok=True)

# files we want to download
files = ["aluminum_shark.tar", 'tensorflow-2.7.0-cp38-cp38-linux_x86_64.whl']

# get latest release
headers = {
    "Accept": "application/vnd.github+json",
    "Authorization": f"Bearer {token}",
    "X-GitHub-Api-Version": "2022-11-28"
}
url = "https://api.github.com/repos/inspire-lab/aluminum_shark/releases/latest"

response = requests.get(url=url, headers=headers)
if not response.ok:
  print(response)
  print(response.json())
  exit(1)

# modify headers for downloading
headers["Accept"] = "application/octet-stream"

response_json = response.json()
assets = response_json["assets"]
for a in assets:
  if a["name"] in files:
    # download the file
    url = a["url"]
    response = requests.get(url=url, headers=headers)
    if not response.ok:
      print(response)
      exit(1)
    # write the downloaded file
    bytes = io.BytesIO(response.content)
    with open(os.path.join(dl_dir, a["name"]), 'wb') as f:
      f.write(bytes.getbuffer())
