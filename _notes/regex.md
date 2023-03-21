---
title: Regex notes
---

##### Special characters
```
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

##### Letter selection
```
[a-z]                           # Any letter from 'a' to 'z'
[a-zA-Z0-9]                     # a-z or A-Z or 0-9
[az]                            # 'a' or 'z'
[^az]                           # not 'a' and not 'z' 
```

##### Repetition (after-sign)
```
+                               # One or more times                          
*                               # Zero or more times
?                               # Zero or one
{7}                             # 7 times
{7,}                            # At least 7 times
{7,9}                           # Between 7 to 9 times
```
##### Grouping (word-selection)
```
(test)-\1                       # Parse `test-test`
(ab)-\2 (cd)-\1                 # Parse `ab-cd cd-ab`
(?:ab)-/1 (cd)                  # First group is not captured
(test|TeSt)                     # `test` or `TeSt`
```

##### Lookahead / lookbehind
```
# Lookahead (if something is after)
\d(?=PM)                        # From `9AM 1PM` parse `1`
\d(?!PM)                        # From `9AM 1PM` parse `9`

# Lookbehind (if something is before)      
(?<=\$)\d                       # From `PLN5 $2` parse `2`
(?<!\$)\d                       # From `PLN5 $2` parse `5`
```

##### Modifiers (flags)
```
/test/g                         # Global (parse all matches)
/test/m                         # Multiline (each line separately)
/test/i                         # Case insensitive
```