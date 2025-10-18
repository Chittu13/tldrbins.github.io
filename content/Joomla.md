---
title: "Joomla"
tags: ["Joomla", "Cms", "Web Exploitation"]
---

### Check Version

```console
curl -s <TARGET>/administrator/manifests/files/joomla.xml | head
```

---

### Admin Panel

```console
curl -s <TARGET>/administrator
```
