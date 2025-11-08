#!/bin/bash
###################################################################################################
#  DESCRIPTION:                                                                                   #
#  This script was designed to be executed by a NagiosXI Event Handler to run AAP Templates       #
#  The tough thing about Nagios event handlers is using the correct host name value so it         #
#   matches the inventory value in AAP. Modify line 84 in this script to make that work for you   #
#                                                                                                 #
#   Company: OsbornePro LLC.                                                                      #
#   Website: https://osbornepro.com                                                               #
#   Author: Robert H. Osborne                                                                     #
#   Contact: rosborne@osbornepro.com                                                              #
###################################################################################################
# Define the user ID of the local AAP user you are authenticating to AAP with
USER_ID=8
USAGE="
#===============================================#
#   ___     _                      ___          #
#  / _ \ __| |__  ___ _ _ _ _  ___| _ \_ _ ___  #
# | (_) (_-< '_ \/ _ \ '_| ' \/ -_)  _/ '_/ _ \ #
#  \___//__/_.__/\___/_| |_||_\___|_| |_| \___/ #
#-----------------------------------------------#
#      If you can't beat 'em, tech 'em!         #
#===============================================#
SYNTAX:
    $0 [-h] -H <AAP_HOST> -A <username> -X <password_or_token> -T <job_template_id> -t <target_host> -s <service_name> -S <state_type> -a <state> -o <output> -g <hostgroups> -d <drive_letter>

DESCRIPTION:
    This script is for executing a Nagios Event Handler that runs ansible playbooks via the AAP API
    Documentation at https://developers.redhat.com/api-catalog/api/ansible-automation-controller

REQUIREMENTS:
    1.) You should have local Semaphore admin account credentials to authenticate to Semaphore
    2.) Define $USER#$ variables in your /usr/local/nagios/etc/resource.cfg file containing the Sempahore username and password 
    3.) Create a command in Nagios that runs this script, passing along the $USER$ variables for the -A and -X parameters in this script
         $USER1$/check_ncpa.py 

CONTACT INFORMATION
    Company: Vinebrook Technology Inc.
    Website: https://www.vinebrooktechnology.com
    Author: Robert Osborne (Vinebrook Technology)
    Contact: rosborne@vinebrooktech.com

USAGE: aap_api_call.sh [-h] -H <AAP_HOST> -A <username> -X <password_or_token> -T <job_template_id> -t <target_host> -s <service_name> -S <state_type> -a <state> -o <output> -g <hostgroups> -d <drive_letter>

OPTIONS:
    -H : AAP host URL (e.g. https://ansible.domain.com)
    -A : Username (or 'token' if using API token)
    -X : Password or API token
    -T : Job Template ID in AAP
    -t : Target host (limit)
    -s : Service name
    -S : Service state type (HARD/SOFT)
    -a : Service state (OK/WARNING/CRITICAL)
    -o : Service output
    -g : Host group names
    -d : Drive letter

EXAMPLES:
    aap_api_call.sh -h
    # This example returns the help information on how to use this command

    aap_api_call.sh -H https://ansible.domain.com -A token -X tokenvaluehere -T 94 -t server01
    # This example runs task 94 against target_host server01
"
LOG_FILE="/tmp/run-aap-playbook.log"

function log_message() {
    /usr/bin/echo "$(/usr/bin/date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

# Print usage
function print_usage {
    /bin/printf "$USAGE\n" >&2
    exit 3
}  # End function print_usage

# Parse arguments
while getopts "hH:A:X:T:t:s:S:a:o:g:d:" OPTION; do
    case $OPTION in
        h) print_usage ;;
        H) AAP_HOST="${OPTARG}" ;;
        A) AUTHUSERNAME="${OPTARG}" ;;
        X) AUTHPASSWORD="${OPTARG}" ;;
        T) JOB_TEMPLATE_ID="${OPTARG}" ;;
        t) TARGET_HOST=$(echo "${OPTARG%%.*}" | tr '[:lower:]' '[:upper:]')'*' ;;
        s) SERVICE_NAME="$OPTARG" ;;
        S) SERVICE_STATE_TYPE="$OPTARG" ;;
        a) SERVICE_STATE="$OPTARG" ;;
        o) SERVICE_OUTPUT="$OPTARG" ;;
        g) HOST_GROUP_NAMES="$OPTARG" ;;
        d) DRIVE_LETTER="$OPTARG" ;;
        *) print_usage ;;
    esac
done

SERVICE_STATE_TYPE=${SERVICE_STATE_TYPE:-"UNDEFINED"}
log_message "[-] SERVICE_STATE_TYPE is '${SERVICE_STATE_TYPE}'"

if [ "${SERVICE_STATE,,}" == "ok" ]; then
    log_message "[-] Service state is OK. Exiting without triggering playbook."
    exit 0
fi

if [ "$SERVICE_STATE_TYPE" != "HARD" ] && [ ${#SERVICE_STATE_TYPE} -lt 2 ]; then
    log_message "[-] Not HARD state. Exiting."
    exit 0
fi

if [ -z "$AAP_HOST" ] || [ -z "$JOB_TEMPLATE_ID" ] || [ -z "$TARGET_HOST" ]; then
    log_message "[x] Required arguments missing"
    print_usage
fi

# Set base API path for Controller
AAP_API_BASE="${AAP_HOST}/api/controller/v2"

# Build authentication header
if [ "$AUTHUSERNAME" == "token" ]; then
    AUTH_HEADER="Authorization: Bearer $AUTHPASSWORD"
else
    # Get user ID
    USERS_RESPONSE=$(/usr/bin/curl -v -sk -u "$AUTHUSERNAME:$AUTHPASSWORD" \
        "$AAP_API_BASE/users/?username=$AUTHUSERNAME" 2>> "$LOG_FILE")
    log_message "[-] Raw USERS_RESPONSE: $USERS_RESPONSE"

    if ! echo "$USERS_RESPONSE" | /usr/bin/jq -e . >/dev/null 2>&1; then
        log_message "[x] USERS_RESPONSE is not valid JSON"
        exit 1
    fi

    log_message "[-] User ID: $USER_ID"

    # Create PAT
    TOKEN_RESPONSE=$(/usr/bin/curl -v -sk -u "$AUTHUSERNAME:$AUTHPASSWORD" -X POST \
        -H "Content-Type: application/json" \
        -d "{\"description\": \"Nagios Auto Token\", \"scope\": \"write\"}" \
        "${AAP_API_BASE}/users/${USER_ID}/personal_tokens/" 2>> "$LOG_FILE")

    log_message "[-] Raw TOKEN_RESPONSE: $TOKEN_RESPONSE"

    if ! echo "$TOKEN_RESPONSE" | /usr/bin/jq -e . >/dev/null 2>&1; then
        log_message "[x] TOKEN_RESPONSE is not valid JSON"
        exit 1
    fi

    ACCESS_TOKEN=$(/usr/bin/echo "$TOKEN_RESPONSE" | /usr/bin/jq -r '.token')
    if [ -z "$ACCESS_TOKEN" ] || [ "$ACCESS_TOKEN" = "null" ]; then
        log_message "[x] Failed to create PAT. Response: $TOKEN_RESPONSE"
        exit 1
    fi
    AUTH_HEADER="Authorization: Bearer $ACCESS_TOKEN"
    log_message "[-] PAT created successfully (truncated for log)."
fi

# Check how many jobs are running
JOBS_RESPONSE=$(/usr/bin/curl -v -sk -H "$AUTH_HEADER" \
    "$AAP_API_BASE/jobs/?status__in=running,pending" 2>> "$LOG_FILE")
log_message "[-] Raw JOBS_RESPONSE: $JOBS_RESPONSE"

if ! echo "$JOBS_RESPONSE" | /usr/bin/jq -e . >/dev/null 2>&1; then
    log_message "[x] JOBS_RESPONSE is not valid JSON"
    exit 1
fi

JOB_COUNT=$(/usr/bin/echo "$JOBS_RESPONSE" | /usr/bin/jq '.count')

log_message "[-] Found $JOB_COUNT running/pending jobs."
if [ "$JOB_COUNT" -ge 4 ]; then
    log_message "[!] Too many jobs running. Skipping."
    /usr/bin/echo "Too many AAP jobs running. Exiting."
    exit 0
fi

# Build payload
PAYLOAD="{\"limit\": \"${TARGET_HOST}\", \"extra_vars\": {\"service_name\":\"${SERVICE_NAME}\", \"drive_letter\":\"${DRIVE_LETTER}\"}}"
log_message "[-] Payload: $PAYLOAD"

# Launch the job
LAUNCH_RESPONSE=$(/usr/bin/curl -v -sk -X POST \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" \
    "$AAP_API_BASE/job_templates/${JOB_TEMPLATE_ID}/launch/" 2>> "$LOG_FILE")

if [ $? -ne 0 ]; then
    log_message "[x] Failed to launch job. Response: $LAUNCH_RESPONSE"
    exit 1
else
    log_message "[-] Job launched successfully." # Response: $LAUNCH_RESPONSE"
fi

log_message "[-] Script execution completed."
