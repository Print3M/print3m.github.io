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

## Tools

`Cewl` tool crawles through a website and generates a wordlist specific to a given target. The generated wordlist might include employee names, locations and brand names.

```bash
cewl
    -w <file>       # Output file
    -m <num>        # Collect words with length >= 5
    -d <num>        # Depth level of crawling
    <url>           # Url to be crawled
```
