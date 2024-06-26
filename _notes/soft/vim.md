---
title: VIM notes
---

## Modes
VIM has two basic modes of working:

- INSERT mode - write text as if in normal text editor
- NORMAL mode - navigate, manipulate and execute commands

```text
ESC - enter NORMAL mode
i   - enter INSERT mode
```

## Moving cursor

```text
Word context:
w                                       # Start of the next word
e                                       # End of the word
b                                       # Beginning of the word
5w                                      # Execute `b` 5 times

Go to line:
:<num>                                  # Go to :num line
:$                                      # End of a file
```

## Insert

```text
<num>i<phrase> + ESC                    # Insert :phrase :num times
```

## Delete lines

```text
:<params>d                              # Pattern 
:<start>,<end>d                         # Delete lines in range
:%d                                     # All lines
:.d                                     # Current line
:$d                                     # Last line
:.,$d                                   # From current to last line
:g/<regex>/d                            # Delete lines matching regex
```

## Options
> **NOTE**: To persist configuration write certain options into .vimrc file in user's home directory.

```text
:set <option>                           # Set option
:set no<option>                         # Unset option

:set number                             # Display line numbers
:syntax on                              # Turn on syntax highlighting
```

## Changing opened file

```text
CTRL + SHIFT + I                        # Last opened file (back)
CTRL + SHIFT + O                        # Last opened file (next)
:e.                                     # Open directory listing     
```
