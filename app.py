from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import subprocess
import os

app = Flask(__name__)
CORS(app)


def run_command(command):
    try:
        result = subprocess.run(f'sudo {command}', shell=True, text=True, capture_output=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return "No data to show"


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/<action>', methods=['GET', 'POST'])
def api(action):
    if request.method == 'GET':
        if action == 'show_faillock_all_users':
            command = 'sudo faillock'
        elif action == 'show_unlock_time':
            command = "grep unlock_time /etc/security/faillock.conf /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/sshd"
        elif action == 'show_deny_value':
            command = "grep deny /etc/security/faillock.conf /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/sshd"
        elif action == 'show_last_30_log_entries':
            command = "[ -e /var/log/secure ] && LOGFILE=/var/log/secure || ([ -e /var/log/auth ] && LOGFILE=/var/log/auth) && sudo tail -n 30 $LOGFILE"
        elif action == 'show_login_attempts':
            command = "[ -e /var/log/secure ] && LOGFILE=/var/log/secure || ([ -e /var/log/auth ] && LOGFILE=/var/log/auth) && sudo cat $LOGFILE | grep -E 'gdm-password.*authentication failure|sshd.*Failed|Account temporary locked|sshd.*Accepted|gdm-password.*session opened for user'"
        elif action == 'generate_logins_report':
            command = """
                PRIMARY_LOGFILE="/var/log/secure"
                BACKUP_LOGFILE="/var/log/auth.log"
                if [[ -f "$PRIMARY_LOGFILE" ]]; then
                    LOGFILE="$PRIMARY_LOGFILE"
                elif [[ -f "$BACKUP_LOGFILE" ]]; then
                    LOGFILE="$BACKUP_LOGFILE"
                else
                    echo "Neither $PRIMARY_LOGFILE nor $BACKUP_LOGFILE is present. Exiting."
                    exit 1
                fi
                echo -e
                echo "Report started at: $(date '+%a %b %d %T %Z %Y')" && echo -e
                echo -e "\\nUsers logged in: $(who -urb)"
                echo -e "\\nAmount of users logged in: $(who -urbq)\n"
                echo "========== Authentication Report ==========" && echo -e
                echo -n "Graphical GDM - Accepted Logins: "
                sudo cat "$LOGFILE" | grep -E "gdm-password.*session opened for user" | wc -l && echo -e
                echo -n "Graphical GDM - Failed Logins: "
                sudo cat "$LOGFILE" | grep "gdm-password.*authentication failure" | wc -l && echo -e
                echo -n "SSHD - Succeeded Logins: "
                sudo cat "$LOGFILE" | grep -E "sshd.*Accepted" | wc -l && echo -e
                echo -n "SSHD - Failed Logins: "
                sudo cat "$LOGFILE" | grep "sshd.*Failed" | wc -l && echo -e
                echo -n "Account Temporary Locks: "
                sudo cat "$LOGFILE" | grep "account temporary locked" | wc -l && echo -e
                echo "--------------------------------------------"
                echo -e "           LINUX SYSTEM INFO             "
                echo -e "\\n$(cat /etc/os-release)"
                echo -e "\\n$(uname -a)"
                echo -e "\\n$(ip addr)"
                echo -e "\\nSystem uptime info: $(uptime -s && uptime -p)"
                echo -e "\\nReport ended at: $(date "+%a %b %d %T %Z %Y")"
            """
        elif action == 'show_faillock_specific_user':
            user = request.args.get('user', '')
            if user:
                command = f'sudo faillock --user {user}'
            else:
                return "Error: user is required", 400
        else:
            return "Error: Invalid action", 400

        output = run_command(command)
        return output

    elif request.method == 'POST':
        if action == 'unlock':

            unlock_time = request.json.get('unlock_time')
            if unlock_time is not None:

                try:

                    unlock_time = int(unlock_time)

                except ValueError:

                    return "Error: unlock_time must be an integer", 400
            else:

                return "Error: unlock_time is required", 400

            command = (
                f"sed -i 's/unlock_time=[0-9]*/unlock_time={unlock_time} /g' "
                "/etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/sshd /etc/security/faillock.conf && grep unlock_time /etc/security/faillock.conf /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/sshd"
            )

        elif action == 'deny':

            deny_value = request.json.get('deny_value')
            if deny_value is not None:

                try:
                    deny_value = int(deny_value)

                except ValueError:

                    return "Error: deny_value must be an integer", 400
            else:

                return "Error: deny_value is required", 400

            command = (
                f"sed -i 's/deny=[0-9]*/deny={deny_value} /g' "
                "/etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/sshd /etc/security/faillock.conf && grep deny /etc/security/faillock.conf /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/sshd"
            )



        elif action == 'allow_even_deny_root':
            command = (
                "sed -i 's/^#even_deny_root/even_deny_root/' /etc/security/faillock.conf && echo " " && echo 'Enabled even_deny_root in /etc/security/faillock.conf:' && echo " " && grep even_deny_root /etc/security/faillock.conf")


        elif action == 'deny_even_deny_root':
            command = (
                "sed -i 's/^even_deny_root/#even_deny_root/' /etc/security/faillock.conf && echo " " && echo 'Disabled even_deny_root in /etc/security/faillock.conf:' && echo " " && grep even_deny_root /etc/security/faillock.conf")

    else:

        return "Error: Invalid action", 400

    return run_command(command)


@app.route('/api/sshd_status_log', methods=['GET'])
def sshd_status_log():
    log_file_path = 'sshd_status.log'
    try:
        with open(log_file_path, 'r') as log_file:
            log_content = log_file.read()
        return log_content
    except Exception as e:
        return str(e)


@app.route('/api/sshd', methods=['GET', 'POST'])
def sshd_api():
    # Handling both GET and POST requests
    if request.method == 'GET':
        command = request.args.get('command', '')
    elif request.method == 'POST':
        command = request.form.get('command', '')  # For form data
        if not command:
            command = request.json.get('command', '')  # For JSON data

    # Create the log file and execute the SSHD command
    sshd_log = "touch sshd_status.log"
    os.system(sshd_log)
    sshd_command = f"sudo service sshd {command} > sshd_status.log 2>&1"
    output = run_command(sshd_command)

    # Automatically check the status after starting, stopping, or restarting SSHD
    if command in ['start', 'stop', 'restart']:
        status_command = "sudo service sshd status"
        status_output = run_command(status_command)
        return status_output

    # If the command was 'status', return the log content directly
    with open('sshd_status.log', 'r') as log_file:
        output = log_file.read()
        return output


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
