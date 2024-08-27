from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import subprocess
import os

app = Flask(__name__)
CORS(app)

# Determine the correct log file at the start
def determine_logfile():
    if os.path.exists('/var/log/auth.log'):
        return '/var/log/auth.log'
    elif os.path.exists('/var/log/secure'):
        return '/var/log/secure'
    else:
        return None

LOGFILE = determine_logfile()

def run_command(command):
    try:
        result = subprocess.run(f'sudo {command}', shell=True, text=True, capture_output=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        return "No data to show"

def run_command_no_sudo(command):
    try:
        result = subprocess.run(f'{command}', shell=True, text=True, capture_output=True, check=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}")
        return "No data to show"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/clock')
def get_server_time():
    server_datetime = subprocess.check_output("date '+%Y-%m-%d %H:%M:%S'", shell=True).decode().strip()
    return jsonify(datetime=server_datetime)

@app.route('/api/<action>', methods=['GET', 'POST'])
def api(action):
    if request.method == 'GET':
        if action == 'show_last_locked_user':
            command = f"grep 'pam_faillock(sshd:auth): Consecutive login failures for user' {LOGFILE} | tail -n 1 && grep 'pam_faillock(gdm-password:auth): Consecutive login failures for user' {LOGFILE} | tail -n 1"
            output = run_command_no_sudo(command)
            return output

        elif action == 'show_all_user_lockouts':
            user = request.args.get('user', '').strip()
            if user:
                # Check if the user exists
                user_exists_command = f"getent passwd {user} > /dev/null"
                user_exists = subprocess.run(user_exists_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                if user_exists.returncode == 0:
                    # User exists, now check for lockouts
                    command = f"""
                        grep -E "pam_faillock\\((sshd|gdm-password):auth\\): Consecutive login failures for user {user}" {LOGFILE}
                    """
                    output = run_command(command)
                    if output:
                        return output
                    else:
                        return f"No lockout data found for user: {user}", 200
                if user_exists.returncode == 1:
                    command = f"""
                        echo "Could not determine entries for user {user} in {LOGFILE}
                    """
                    output = run_command(command)
                    if output:
                        return output
                else:
                    # User does not exist
                    command = f"""
                        echo "Error: Unable to show lockouts for user: '{user}' does not exist in this system."
                        echo "------------------------------------------------------------------------------"
                        echo "Listing all existing users in the system:"
                        echo "------------------------------------------------------------------------------"
                        awk -F: '$3 >= 1000 {{print $1}}' /etc/passwd
                        echo "------------------------------------------------------------------------------"
                        date
                    """
                    output = run_command(command)
                    return output
            else:
                command = f"""
                    echo "Error: User parameter is required."
                    echo "------------------------------------------------------------------------------"
                    echo "Listing all existing users in the system:"
                    echo "------------------------------------------------------------------------------"
                    awk -F: '$3 >= 1000 {{print $1}}' /etc/passwd
                    echo "------------------------------------------------------------------------------"
                    date
                """
                output = run_command(command)
                if output:
                    return output
                else:
                    return f"No lockout data found for user: {user}", 200

        elif action == 'unlock_user':
            unlock_a_user = request.args.get('unlock_a_user', '').strip()

            if unlock_a_user:
                # Check if the user exists
                unlock_a_user_exists_command = f"getent passwd {unlock_a_user} > /dev/null"
                unlock_a_user_exists = subprocess.run(unlock_a_user_exists_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

                if unlock_a_user_exists.returncode == 0:
                    # User exists, attempt to unlock
                    command = f"""
                        sudo faillock --user {unlock_a_user} --reset &>/dev/null
                        if [ $? -eq 0 ]; then
                            echo "Successfully ran unlock operation for user: {unlock_a_user}"
                        else
                            echo "Failed to unlock user: {unlock_a_user}. Command failed."
                        fi
                        echo
                        echo "---------------------------------------------------------"
                        date
                    """
                    output = run_command(command)
                    return output
                else:
                    # User does not exist
                    command = f"""
                        echo "Error: Unable to unlock user: '{unlock_a_user}' does not exist in this system."
                        echo "------------------------------------------------------------------------------"
                        echo "Listing all existing users in the system:"
                        echo "------------------------------------------------------------------------------"
                        awk -F: '$3 >= 1000 {{print $1}}' /etc/passwd
                        echo "------------------------------------------------------------------------------"
                        date
                    """
                    output = run_command_no_sudo(command)
                    return output
            else:
                # No user parameter provided
                command = f"""
                    echo "Error: No user provided. Please specify a username."
                    echo "------------------------------------------------------------------------------"
                    echo "Listing all existing users in the system:"
                    echo "------------------------------------------------------------------------------"
                    awk -F: '$3 >= 1000 {{print $1}}' /etc/passwd
                    echo "------------------------------------------------------------------------------"
                    date
                """
                output = run_command_no_sudo(command)
                return output

        elif action == 'show_unlock_time':
            command = "grep unlock_time /etc/security/faillock.conf /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/sshd /etc/pam.d/gdm-password"
            return run_command_no_sudo(command)

        elif action == 'show_deny_value':
            command = "grep deny /etc/security/faillock.conf /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/sshd /etc/pam.d/gdm-password"
            return run_command_no_sudo(command)

        elif action == 'show_last_30_log_entries':
            command = f"tail -n 30 {LOGFILE}"
            return run_command_no_sudo(command)

        elif action == 'generate_logins_report':
            command = f"""
                echo
                echo "Report started at: $(date '+%a %b %d %T %Z %Y')"
                echo
                echo "Users logged in: $(who -urb)"
                echo
                echo "Amount of users logged in: $(who -urbq)"
                echo
                echo "========== Authentication Report =========="
                echo
                echo -n "Graphical GDM - Accepted Logins: "
                grep -c 'gdm-password.*session opened for user' {LOGFILE}
                echo
                echo -n "Graphical GDM - Failed Logins: "
                grep -c 'gdm-password.*authentication failure' {LOGFILE}
                echo
                echo -n "SSHD - Succeeded Logins: "
                grep -c 'sshd.*Accepted' {LOGFILE}
                echo
                echo -n "SSHD - Failed Logins: "
                grep -c 'sshd.*Failed password' {LOGFILE}
                echo
                echo -n "Account Temporary Locks: "
                grep -c 'pam_faillock.*account temporary locked' {LOGFILE}
                echo
                echo "--------------------------------------------"
                echo "           LINUX SYSTEM INFO             "
                echo
                cat /etc/os-release
                echo
                uname -a
                echo
                ip addr
                echo
                echo "System uptime info: $(uptime -s && uptime -p)"
                echo
                echo "Report ended at: $(date '+%a %b %d %T %Z %Y')"
            """
            return run_command_no_sudo(command)

        elif action == 'show_login_attempts':
            command = f"cat {LOGFILE}"
            return run_command_no_sudo(command)

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
                f"sed -i 's/unlock_time=[0-9]*/unlock_time={unlock_time}/g' "
                "/etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/sshd /etc/pam.d/gdm-password /etc/security/faillock.conf && grep unlock_time /etc/security/faillock.conf /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/sshd /etc/pam.d/gdm-password"
            )
            return run_command(command)

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
                f"sed -i 's/deny=[0-9]*/deny={deny_value}/g' "
                "/etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/sshd /etc/pam.d/gdm-password /etc/security/faillock.conf && grep deny /etc/security/faillock.conf /etc/pam.d/system-auth /etc/pam.d/password-auth /etc/pam.d/sshd /etc/pam.d/gdm-password"
            )
            return run_command(command)

    return jsonify({"error": "Invalid action or method"}), 400

@app.route('/api/sshd', methods=['GET', 'POST'])
def sshd_api():
    # Handling both GET and POST requests
    if request.method == 'GET':
        command = request.args.get('command', '')
    elif request.method == 'POST':
        command = request.form.get('command', '')  # For form data
        if not command:
            command = request.json.get('command', '')  # For JSON data

    if not command:
        command = request.json.get('command', '')  # For JSON data
    # Create the log file and execute the GDM command
    sshd_log = "touch sshd_status.log"
    os.system(sshd_log)
    sshd_command = f"sudo service sshd {command} > sshd_status.log 2>&1"
    # Execute the command and return the output
    output = run_command(sshd_command)
    return output

    # Automatically check the status after starting, stopping, or restarting SSHD
    if command in ['start', 'stop', 'restart']:
        status_command = "sudo service sshd status"
        status_output = run_command(status_command)
        return status_output

    # If the command was 'status', return the log content directly
    with open('sshd_status.log', 'r') as log_file:
        output = log_file.read()
        return output

@app.route('/api/sshd_status_log', methods=['GET'])
def sshd_status_log():
    log_file_path = 'sshd_status.log'
    try:
        with open(log_file_path, 'r') as log_file:
            log_content = log_file.read()
        return log_content
    except Exception as e:
        return str(e)

@app.route('/api/gdm', methods=['GET', 'POST'])
def gdm_api():
    # Handling both GET and POST requests
    if request.method == 'GET':
        command = request.args.get('command', '')
    elif request.method == 'POST':
        command = request.form.get('command', '')  # For form data
        if not command:
            command = request.json.get('command', '')  # For JSON data

    # Create the log file and execute the GDM command
    gdm_log = "touch gdm_status.log"
    os.system(gdm_log)
    gdm_command = f"sudo service gdm {command} > gdm_status.log 2>&1"
    output = run_command(gdm_command)

    # Automatically check the status after starting, stopping, or restarting GDM
    if command in ['start', 'stop', 'restart']:
        status_command = "sudo service gdm status"
        status_output = run_command(status_command)
        return status_output

    # If the command was 'status', return the log content directly
    with open('gdm_status.log', 'r') as log_file:
        output = log_file.read()
        return output

@app.route('/api/gdm_status_log', methods=['GET'])
def gdm_status_log():
    log_file_path = 'gdm_status.log'
    try:
        with open(log_file_path, 'r') as log_file:
            log_content = log_file.read()
        return log_content
    except Exception as e:
        return str(e)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
