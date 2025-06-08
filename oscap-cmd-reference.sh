# This is a collection of commands that can be used for SCAP compliance
#################################
# SETUP OPENSCAP
#################################
# Install OpenSCAP
sudo dnf install -y scap-security-guide openscap-scanner

# Make folder for reports
sudo mkdir -p /usr/share/openscap/reports
sudo cd /usr/share/openscap/reports
sudo umask 077
sudo chown root:root -R /usr/share/openscap/reports

#################################
# PREPARE FOR SCAN
#################################
# View available data streams
sudo ls -la /usr/share/xml/scap/ssg/content

# List Profiles in a data stream
sudo oscap info /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml

#################################
# SCAN AND EXPORT HTML
#################################
# CIS Server Level 1
sudo oscap xccdf eval --report /usr/share/openscap/reports/scan-report.html --profile xccdf_org.ssgproject.content_profile_cis_server_l1 /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml
# CIS Server Level 2
sudo oscap xccdf eval --report /usr/share/openscap/reports/scan-report.html --profile xccdf_org.ssgproject.content_profile_cis /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml
# CIS Workstation Level 1
sudo oscap xccdf eval --report /usr/share/openscap/reports/scan-report.html --profile xccdf_org.ssgproject.content_profile_cis_workstation_l1 /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml
# CIS Workstation Level 2
sudo oscap xccdf eval --report /usr/share/openscap/reports/scan-report.html --profile xccdf_org.ssgproject.content_profile_cis_workstation_l2 /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml
# PCI-DSS v4.0.1
sudo oscap xccdf eval --report /usr/share/openscap/reports/scan-report.html --profile xccdf_org.ssgproject.content_profile_pci-dss /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml

#################################
# SCAN AND GENERATE REMEDIATION
#################################
# *** WARNING WARNING WARNING ***************************************************
# Review this before running it! It will make significant changes to the system.
# I typically remove some password settings for domain joined devices
# I also may need services like nfs-server if i need it
#********************************************************************************
# 1.) Generate Scan Results
sudo oscap xccdf eval --results /usr/share/openscap/reports/openscap-scan-results.xml --profile xccdf_org.ssgproject.content_profile_cis /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml
# 2.) Generate Bash Script for remediation
sudo oscap xccdf generate fix --output "/usr/local/sbin/$(hostname)-scap-remediation.sh" --profile xccdf_org.ssgproject.content_profile_cis /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml
# Generate ansible playbook for remediation
sudo oscap xccdf generate fix --fix-type ansible --output "~ansible/ansible/playbooks/$(hostname)-scap-remediation.yml" --profile xccdf_org.ssgproject.content_profile_cis /usr/share/xml/scap/ssg/content/ssg-rl9-ds.xml

#################################
# APACHE SCAP COMPLIANCE
#################################
# Install requirements
sudo dnf install -y httpd mod_ssl
# Configuration Changes
sed -i 's/^\([^#].*\)**/# \1/g' /etc/httpd/conf.d/welcome.conf
dnf -y remove httpd-manual
dnf -y install mod_session

echo "MaxKeepAliveRequests 100" > /etc/httpd/conf.d/disa-apache-stig.conf
echo "SessionCookieName session path=/; HttpOnly; Secure;" >>  /etc/httpd/conf.d/disa-apache-stig.conf
echo "Session On" >>  /etc/httpd/conf.d/disa-apache-stig.conf
echo "SessionMaxAge 600" >>  /etc/httpd/conf.d/disa-apache-stig.conf
echo "SessionCryptoCipher aes256" >>  /etc/httpd/conf.d/disa-apache-stig.conf
echo "Timeout 10" >>  /etc/httpd/conf.d/disa-apache-stig.conf
echo "TraceEnable Off" >>  /etc/httpd/conf.d/disa-apache-stig.conf
echo "RequestReadTimeout 120" >> /etc/httpd/conf.d/disa-apache-stig.conf

sed -i "s/^#LoadModule usertrack_module/LoadModule usertrack_module/g" /etc/httpd/conf.modules.d/00-optional.conf
sed -i "s/proxy_module/#proxy_module/g" /etc/httpd/conf.modules.d/00-proxy.conf
sed -i "s/proxy_ajp_module/#proxy_ajp_module/g" /etc/httpd/conf.modules.d/00-proxy.conf
sed -i "s/proxy_balancer_module/#proxy_balancer_module/g" /etc/httpd/conf.modules.d/00-proxy.conf
sed -i "s/proxy_ftp_module/#proxy_ftp_module/g" /etc/httpd/conf.modules.d/00-proxy.conf
sed -i "s/proxy_http_module/#proxy_http_module/g" /etc/httpd/conf.modules.d/00-proxy.conf
sed -i "s/proxy_connect_module/#proxy_connect_module/g" /etc/httpd/conf.modules.d/00-proxy.conf

firewall-cmd --zone=public --add-service=https --permanent
firewall-cmd --zone=public --add-service=https
firewall-cmd --reload
systemctl enable httpd
systemctl start httpd

# STIG CONTROLS FOR APACHE
# REFERENCE: https://docs.rockylinux.org/books/disa_stig/disa_stig_part3/
