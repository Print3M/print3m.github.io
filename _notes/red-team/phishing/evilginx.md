---
title: Evilginx Framework
---

## 1. Overview

Evilginx is an advanced phishing framework that acts as a man-in-the-middle (MITM) proxy for stealing credentials and session cookies. It is primarily used to bypass multi-factor authentication (MFA) mechanisms.

> **NOTE**: Evilginx 3.x is the latest version of this tool.

### 1.1. Proxying

Evilginx acts as a MITM proxy, intercepting all traffic between the victim and the legitimate website. It forwards the victim’s requests to the legitimate website and relays the responses back to the victim. When the victim enters their username and password, Evilginx captures these details before forwarding them to the legitimate website.

> **NOTE**: Victims interact with the legitimate website in real time, making the phishing attack difficult to detect!

### 1.2. MFA Bypass

MFA mechanisms like SMS-based codes or authentication apps rely on possession of a second factor. However, Evilginx bypasses MFA by stealing session cookies that represent an authenticated session. Using session cookies directly by an attacker effectively bypasses MFA.

### 1.3. Mitigations & bypasses

1. Client-side JavaScript hostname detection (with obfuscations) is a pretty good MitM-phishing protection technique. Simple JS function can check current `window.location` object for invalid hostname and fail to render content when invalid hostname is detected. The phishing website must have invalid hostname (`window.location` object is provided by a browser and cannot be spoofed).

**Bypass**: Evilginx implements so-called `sub_filters` to dynamically replace certain strings in JS code of the legitimate website effectively overwriting  JS protections.

2. Client-side JS protection can be used with **dynamic code and dynamic strings obfuscation**. Uniquely obfuscated JS function must be delivered to every visitor. It makes defining `sub_filters` rules almost impossible.

**Bypass**: If implemented correctly, there should be no bypass. But it's rarely implemented at all, not to mention correct implementation. Common mistakes is not to randomly obfuscate most important strings.

1. Generate secret token with extremely obfuscated JS, encrypt it with user credentials and verify on the server. This token, for example, might include information about `element.baseURL` of every element on the page to increase MitM-phishing detection. This approach has been adopted by Google and LinkedIn in the past.

**Bypass**:

- a) Reverse token generation algorithm and spoof it (might be really challenging because of the hard obfuscation).
- b) Open a controlled browser in the background (on the Evilginx server side) and type user's credentials in on the legitimate website, generating valid secret token (paid option: Evilginx Pro Evilpuppet module).

## Usage

References:

- [Evilginx documentation](https://help.evilginx.com/)
- [Evilginx executable](https://github.com/kgretzky/evilginx2/releases/latest)

```bash
# REQUIRED: Set Evilginx server domain
config domain $domain

# REQUIRED: Set Evilginx server IPv4
config ipv4 $ip


help                    # Show help
help $topic             # Show detailed help
config                  # Show config
phishlets               # List all available phishlets

# Set phishlet hostname
phishlet hostname $phishlet $domain

# Enable phishlet (now it's ready to go!)
phishlet enable $phishlet

lures                   # List all lures
lures get-url $id       # Get URL for a specific lure
```

### Phishlets

```bash
# Get hosts to put into /etc/hosts file (for localhost testing)
phishlets get-hosts gmail
```

## 2. IMPORTANT

- Remove easter-egg Evilginx headers
- JA4 signature (cyphersuits) must be changed (TLS-related) - CloudFlare use it to detect suspicious traffic. It's something like User-Agent in TCP.

## 3. TODO

- lures
- phishlet

- https://research.aurainfosec.io/pentest/hook-line-and-phishlet/
- https://breakdev.org/evilginx-3-2/
- https://mrd0x.com/browser-in-the-browser-phishing-attack/
- https://breakdev.org/evilginx-3-3-go-phish/
