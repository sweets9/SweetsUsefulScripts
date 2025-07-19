# UsefulScriptRepo
A collection of useful scripts for cyber security, sysadmin, and other tasks

## checkMounts.py
Will detect broken or stale mounts (NFS and SMB supported) and remount the network shares, notifying via email, and ensuring log message is created.

## Setup instructions

# 1. Clone the repo (or pull updates if already cloned)
git clone https://github.com/sweets9/SweetsUsefulScripts.git /root/SweetsUsefulScripts
cd /root/SweetsUsefulScripts
git pull

# 2. Copy the script to your system path (e.g. /root/bin)
cp checkMount.py /root/bin/checkMount.py
chmod +x /root/bin/checkMount.py

# 3. (Optional) Create a .env file for configuration
echo "SEND_NOTIFICATIONS=true
EMAIL_SERVER=mail
EMAIL_PORT=25
EMAIL_FROM=noreply@example.com
EMAIL_TO=admin@example.com " >> /root/bin/.env

# 4. Install Python dependencies 
pip install python-dotenv # if required

# 5. (Optional) Add to crontab for regular checks every 5 minutes
/root/bin/checkMount.py --install

# Quick Update Anytime:
cd /root/SweetsUsefulScripts && git pull && cp checkMount.py /root/bin/checkMount.py && chmod +x /root/bin/checkMount.py
