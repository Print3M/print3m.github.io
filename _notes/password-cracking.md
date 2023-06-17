---
title: Password cracking notes
---

## Default password resources

* [cirt.net](https://cirt.net/passwords)
* [default-password.info](https://default-password.info/)
* [datarecovery.com](https://datarecovery.com/rd/default-passwords/)

## Weak and leaked password wordlists

* [SecLists/Passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords)
* [skullsecurity.org](https://wiki.skullsecurity.org/index.php?title=Passwords)

## Bash tricks

```bash
cat file1.txt file2.txt > combined.txt      # Combine password files
sort combined.txt | uniq -u > cleaned.txt   # Remove duplicates
```

## Passwords list generators

### Cewl
`Cewl` tool crawles through a website and generates a wordlist specific to a given target. The generated wordlist might include employee names, locations and brand names.

```bash
cewl
    -w <file>       # Output file
    -m <num>        # Collect words with length >= 5
    -d <num>        # Depth level of crawling
    <url>           # Url to be crawled
```

### Crunch
`Crunch` tool generates a list of strings based on specified parameters and patterns (`-t <pattern>`).

* @ - lower case alpha char
* , - upper case alpha char
* % - numeric char
* ^ - special char (spaces included)

```bash
crunch <min-chars> <max-chars> <allowed-chars> -o <output-file>

# Example
crunch 2 4 abcd12345 -o out.txt
crunch 2 4 -t pass%% -o out.txt
```

## Offline hash cracking

**NOTE**: To determine a hash format the command: `hashid -m <hash|file>` can be used. `-m` flag prints a corresponding Hashcat mode number.

### Dictionary attack

```bash
hashcat -a 0 -m <mode> <hash> <wordlist> 
```

## Online password attacks

`Hydra` is a versatile tool to perform online password attacks. It's able to crack usernames and passwords to many different services: `ftp`, `smtp`, `ssh`, `http`.

```bash
# Single username, passwords list
hydra -l <username> -P <pass-list> ftp://ip

# Usernames list, passwords list
hydra -L <user-list> -P <pass-list smtp://ip

# Usernames list, single password
hydra -L <user-list> -p <password> ssh://ip
```
