---
title: Regex notes
---

- [1. Special characters](#1-special-characters)
- [2. Char selection](#2-char-selection)
- [3. Repetition (after-sign)](#3-repetition-after-sign)
- [4. Grouping (word-selection)](#4-grouping-word-selection)
- [5. Lookahead / lookbehind](#5-lookahead--lookbehind)
- [6. Modifiers (flags)](#6-modifiers-flags)

## 1. Special characters

```bash
^                               # Beginning of the line
$                               # End of the line
.                               # Any character
\                               # Escape character
\w                              # [a-zA-Z0-9_]
\W                              # not above
\d                              # [0-9]
\D                              # not above
\s                              # Space
\S                              # Non-space
```

## 2. Char selection

```bash
[a-z]                           # Any letter from 'a' to 'z'
[a-zA-Z0-9]                     # a-z or A-Z or 0-9
[az]                            # 'a' or 'z'
[^az]                           # not 'a' and not 'z' 
```

## 3. Repetition (after-sign)

```bash
+                               # One or more times                          
*                               # Zero or more times
?                               # Zero or one
{7}                             # 7 times
{7,}                            # At least 7 times
{7,9}                           # Between 7 to 9 times
```

## 4. Grouping (word-selection)

```bash
(test)-\1                       # Parse `test-test`
(ab)-\2 (cd)-\1                 # Parse `ab-cd cd-ab`
(?:ab)-/1 (cd)                  # First group is not captured
(test|TeSt)                     # `test` or `TeSt`
```

## 5. Lookahead / lookbehind

```bash
# Lookahead (if something is after)
\d(?=PM)                        # From `9AM 1PM` parse `1`
\d(?!PM)                        # From `9AM 1PM` parse `9`

# Lookbehind (if something is before)      
(?<=\$)\d                       # From `PLN5 $2` parse `2`
(?<!\$)\d                       # From `PLN5 $2` parse `5`
```

## 6. Modifiers (flags)

```bash
/test/g                         # Global (parse all matches)
/test/m                         # Multiline (each line separately)
/test/i                         # Case insensitive
```
