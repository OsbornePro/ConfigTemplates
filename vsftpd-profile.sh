#!/bin/bash
USAGE="

SYNTAX: $0 [-h] [-u | -d]


DESCRIPTION:
   This script is used to specify whether the vsftp server should active anonymous downloads or anonymous uploads


REQUIREMENTS:
   1.) The config files must be named vsftpd-anon-downloads.conf and vsftpd-anon-uploads.conf
   2.) Debian OS will auto-set the config directory as /etc Fedora is /etc/vsftpd which are the package installer defaults


CONTACT INFORMATION
   Company: OsbornePro LLC.
   Website: https://osbornepro.com
   Author: Robert H. Osborne
   Contact: rosborne@osbornepro.com


USAGE: $0 [-u | -d]

    OPTIONS:
        -h : Displays the help information for the command.
        -u : Switch VSFTPD server to use Anonymous Uploads Configuration
        -d : Switch VSFTPD server to use Anonymous Downloads Configuration

    EXAMPLES:
        $0 -u
        # On Fedora this example uses the /etc/vsftpd/vsftpd-anon-uploads.conf configuration file with VSFTPD
        # On Debian this example uses the /etc/vsftpd-anon-uploads.conf configuration file with VSFTPD

        $0 -d
        # On Fedora this example uses the /etc/vsftpd/vsftpd-anon-downloads.conf configuration file with VSFTPD
        # On Debian this example uses the /etc/vsftpd-anon-downloads.conf configuration file with VSFTPD

"

function allow_ctrlc {

        # Allow Ctrl+C to stop execution
        trap '
          trap - INT # restore default INT handler
          kill -s INT "$$"
        ' INT

}  # End function allow_ctrlc


function print_usage {

        printf "$USAGE\n" >&2
        exit 1

}  # End function print_usage

function change_configfile {

        cp "${CONFIGFILE}" "${VSFTPDPATH}/vsftpd.conf"

}

function restart_vsftpd_service {

        printf "[*] Restarting the VSFTPD service \n"
        systemctl restart vsftpd.service

}


OSID=$(grep ID_LIKE /etc/os-release | cut -d"=" -f 2)
if [ "$OSID" == '"debian"' ]; then
        printf "[*] Using the Debian based OS settings \n"
        VSFTPDPATH="/etc"
elif [ "$OSID" == '"fedora"' ]; then
        printf "[*] Using the Fedora based OS settings \n"
        VSFTPDPATH="/etc/vsftpd"
else
        printf "[!] Operating system ID is not Debian or Fedora \n"
        exit 1
fi

while [ ! -z "$1" ]; do
        case "$1" in
                -u)
                        shift
                        CONFIGFILE="${VSFTPDPATH}/vsftpd-anon-uploads.conf"
                        printf "[*] Using the UPLOADS configuration \n"
                        ;;
                -d)
                        shift
                        CONFIGFILE="${VSFTPDPATH}/vsftpd-anon-downloads.conf"
                        printf "[*] Using the DOWNLOADS configuration \n"
                        ;;
                *)
                        print_usage
                        ;;
        esac
shift
done

change_configfile
restart_vsftpd_service
