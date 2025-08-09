# with password
python3 sftp_audit.py --host TARGET --port 22 --user USER --password 'XXXX' \
  --upload-dir /Upload --out report.html

# or with a private key
python3 sftp_audit.py --host TARGET --user USER --pkeyfile ~/.ssh/id_rsa \
  --upload-dir /Upload
