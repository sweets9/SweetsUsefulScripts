# UsefulScriptRepo
A collection of useful scripts for cyber security, sysadmin, and other tasks

## checkMounts.py
Will detect broken or stale mounts (NFS and SMB supported) and remount the network shares, notifying via email, and ensuring log message is created.

## Setup instructions

```
# 1. Clone the repo (or pull updates if already cloned)
git clone https://github.com/sweets9/SweetsUsefulScripts.git /root/SweetsUsefulScripts
cd /root/SweetsUsefulScripts
git pull

# 2. Copy the script to your system path (e.g. /root/bin)
cp checkMounts.py /root/bin/checkMounts.py
chmod +x /root/bin/checkMounts.py

# 3. (Optional) Create a .env file for configuration
echo "SEND_NOTIFICATIONS=true
EMAIL_SERVER=mail
EMAIL_PORT=25
EMAIL_FROM=noreply@example.com
EMAIL_TO=admin@example.com " >> /root/bin/.env

# 4. Install Python dependencies 
pip install python-dotenv || apt install python3-dotenv # if required

# 5. (Recommended) Add to crontab for regular checks every 5 minutes
/root/bin/checkMounts.py --install

# 6. (Recommended) Create sentinel file to check if share is really up or not
# Note: Only run if all shares are correctly mounted and functioning otherwise will create the sentinel file in a dead path
awk '$3 ~ /nfs|cifs/ {print $2}' /etc/fstab | while read m; do mountpoint -q "$m" && touch "$m/.checkMount"; done

# Quick Update Anytime:
cd /root/SweetsUsefulScripts && git pull && cp checkMounts.py /root/bin/checkMounts.py && chmod +x /root/bin/checkMounts.py
```
