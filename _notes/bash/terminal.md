---
title: Linux terminal notes
---

## Configuration

```bash
/etc/default/*                          # Configs of OS boot services
```

## Compression and archives

```bash
tar -xf <arch.tar.gz>                   # Decompress and extract files
tar -cf <arch.tar> <file1> <file2>      # Create archive
tar -caf <arch.tar.gz> <f1> <f2>        # Compress and create archive
tar -tvf <arch.tar>                     # List content (verbosely)
```

## Processes

```bash
pidof <name>                            # Get PID(s) of process(es)
pidof -s <name>                         # Get single PID of process
pgrep -a <name>                         # List processes commands
ps aux | grep <name>                    # Find process by name
ps -fp $(pidof -s <name>)               # Get process info by PID

kill -l                                 # List all signals
kill -9 <PID>                           # Kill process
```

## Users

```bash
# /etc/passwd schema:
#   username:password:UID:GID:comment:home:shell

w                                       # Show who is logged in
last                                    # Show last logged-in users
cat /etc/passwd                         # List all users
id <username>                           # Show user's info                    
    
adduser <username>                      # Add user
passwd <username>                       # Change user's password
usermod -l <new_name> <old_name>        # Change username
userdel -r <username>                   # Delete user and home dir

su <username>                           # Switch to user
sudo <username> <command>               # Exec command as other user
```

## Groups

```bash
# /etc/group schema:
#   groupname:password:GID:group members

cat /etc/group                          # List all groups
groups <username>                       # List user's groups
    
usermod -aG <group> <username>          # Add user to group
gpasswd -d <username <group>            # Remove user from group
```

## Permissions
Permissions priority: User -> Group -> Other

```bash
ls -l                                  # Check permissions
stat <file>                            # Info about access

chown <username> <file>                # Change owner of <file>
chown <username>:<group> <file>        # Change owner and group
chown -R <username> <dir>              # Change dir and its content

chmod u=rwx,g=r,o= <file>              # Change file permissions
chmod ug=rw <file>                     # Change file permissionss
```

## Package management
Repositories are defined in:

- `/etc/apt/sources.list.d/`
- `/etc/apt/sources.list`

```bash
apt update                              # Update local pkgs DB
apt list --upgradable                   # Show packages to be upgraded

apt install <pkg>                       # Install package
apt remove <pkg> --purge                # Remove package
apt upgrade                             # Upgrade all packages
apt install <pkg> --only-upgrade        # Upgrade one package
    
apt changelog <pkg>                     # Show pkg changelog
apt check                               # Check dependencies

apt-cache stats                         # Show pkgs stats
apt-cache search <pkg>                  # Search for pkg
apt-cache show <pkg>                    # Get pkg info        
apt-cache policy <pkg>                  # Get pkg version info        

apt autoclean                           # Clean cache
apt autoremove                          # Remove unnecessary pkgs

dpkg -i <pkg.deb>                       # Install pkg file
dpkg -l                                 # List all installed pkgs
dpkg -L <pkg>                           # List files installed by pkg
```

## Network

```bash
ip a                                    # Show network interfaces
ip link set <iface> down                # Disable interface
ip link set <iface> up                  # Enable interface
ip link set <iface> <mode> on           # Change interface mode

route                                   # Show kernel routes
netstat -tlpn                           # Show open TCP ports
netstat
    -a                                  # Show listening and non-listening
    -l                                  # Show only listening
    -n                                  # Show IP instead of resolved name
    -t                                  # TCP only
    -u                                  # UDP only
    -x                                  # UNIX only
    -p                                  # PID with assigned socket
lsof -i                                 # Show open network connections

# Create tunnel from rhost:rport to lhost:lport
ssh -L <lport>:<lhost>:<rport> <ruser>@<rhost> -fN 
```

## Systemd

```bash
systemctl list-unit-files               # List all unit files
systemctl cat <service>                 # Show unit file
systemctl list-units                    # List all units
systemctl status <service>              # Show service status

systemctl start <service>               # Start service
systemctl stop <service>                # Stop service
systemctl restart <service>             # Restart service
systemctl enable <serivce>              # Start service at boot
systemctl disable <serivce>             # Stop service at boot

journalctl -u <service>                 # Show logs
```

## Sound / speakers

```bash
# With this tool you can set overall levels of sound card
alsamixer                               # ALSA driver mixer
> F6                                    # Select sound card
> ESC                                   # Exit
alsactl store                           # Persist changes
```

## Disks

```bash
cfdisk                                  # User-friendly partition tool
lsblk -fp                               # List disks with partitions
fdisk -l                                # List disks (low-level info)
df -hT                                  # Show disk space
du <dir|file> -hs                       # Show size of file or dir
```

## Memory

```bash
free -h                                 # Show memory stats
watch -n <secs> free -h                 # Show mem stats every N secs
```

## GPU

```bash
lspci -k | grep -EA3 'VGA|3D|Display'   # List available GPUs
nvidia-smi                              # Nvidia GPU & driver info
nvidia-settings                         # GUI Nvidia settings
```

## Kernel

```bash
uname -a                                # Show current kernel version
dpkg -l | grep linux-image              # List installed kernels
```

## Clock

```bash
timedatectl                             # Show OS datetime settings
```

## Environment variables

```bash
env                                     # List all envs
printenv <env-name>                     # Print env value
export <name>=<value>                   # Set env
unset <env-name>                        # Unset env
```

## Job control

```bash
jobs                                    # List all jobs
bg <id>                                 # Place job in bg (running)
<command> &                             # Place job in bg (running)
fg <id>                                 # Place job in fg
CTRL-Z                                  # Stop job
```

## Cron
[CRON time generator.](https://crontab.guru/)

```bash
crontab -l                              # List cron entries
crontab -e                              # Edit cron entries
```

## Cryptography

```bash
openssl genrsa 2048 > rsa.key           # Generate RSA key
```

## Text file manipulation

```bash
# Exclude lines present in both files and save them into :file-3
comm -3 <file-1> <file-2> > <file-3>
```

## Common commands

```bash
shutdown -r now                         # Reboot now
shutdown -P now                         # Shutdown now

uname -a                                # System info
hostnamectl                             # Host info
cat /etc/issue                          # Distro info
cat /etc/shells                         # All available shells

wget <URL> -O <file>                    # Download URL to <file>
wget -i <file>                          # Download URLs from <file>

find <dir> -name <file>                 # Find file/dir in <dir>
find <dir> -type d -name <dir>          # Find directory
find <dir> -type f -name <dir>          # Find file
find <dir> -empty                       # Find empty file/dir
find <dir> -name "*.txt"                # Find .txt files
find <dir> -user <user>                 # Find <user> files
find <dir> -group <group>               # Find <group> files

mkdir -p dir1/dir2/dir3                 # Create nested dirs
ln -s <original> <link>                 # Create soft symbolic link
wc -l <file>                            # Count lines

grep -- "-v"                            # Grep dash pattern
grep -n <str>                           # Grep line numbers
grep -C5 <str>                          # Show 5 lines before and after

sensors                                 # Show temperatures components
```
