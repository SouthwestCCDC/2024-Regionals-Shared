# #APACHE@ BASIC
# Use sed to perform the search and replace operation in security.conf
sudo sed -i "/^#*ServerSignature/c\ServerSignature Off" /etc/apache2/conf-enabled/security.conf
sudo sed -i "/^#*TraceEnable/c\TraceEnable Off" /etc/apache2/conf-enabled/security.conf
sudo sed -i "/^#*ServerTokens/c\ServerTokens Prod" /etc/apache2/conf-enabled/security.conf

sudo sed -i "/^#*Header always unset X-Powered-By/c\Header always unset X-Powered-By" /etc/apache2/conf-enabled/security.conf
sudo sed -i "/^#*FileETag/c\FileETag None" /etc/apache2/conf-enabled/security.conf
sudo sed -i "/^#*Header unset ETag/c\Header unset ETag" /etc/apache2/conf-enabled/security.conf
systemctl restart apache2
echo "APACHE 2 DONE"

