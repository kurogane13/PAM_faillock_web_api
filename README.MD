# PAM Faillock Web API

## AUTHOR: GUSTAVO WYDLER AZUAGA
## VERSION: 1
## RELEASE DATE: 08-13-2024

- Welcome to the PAM Faillock Web API project!
- This API provides a web interface for managing PAM faillock configurations and monitoring authentication logs. 
- It is built using Flask and offers endpoints for interacting with system security settings related to account locking policies.

## Features

- **View Faillock Data**: Retrieve information on account lockout status and failed authentication attempts.
- **Update Faillock Configuration**: Modify lockout settings like unlock time and deny values.
- **Manage SSHD Service daemon**: Start, stop, and restart the SSHD service while checking its status.
- **View Logs**: Access and monitor logs related to SSHD and authentication.

## Installation

To get started with the PAM Faillock Web API, follow these instructions:

### Prerequisites

- **Python 3.x**: Ensure Python 3 is installed on your system.
- **Flask**: A lightweight WSGI web application framework.
- **Flask-CORS**: A Flask extension for handling Cross-Origin Resource Sharing (CORS).
- **`sudo` permissions**: Required for modifying system files and managing services.

### Setup Instructions

1. **Clone the Repository**

   ```bash
   git clone https://github.com/kurogane13/PAM_faillock_web_api.git
   cd PAM_faillock_web_api

2. **Create a Virtual Environment (Recommended)**

   ```bash
    python3.8 -m venv venv
    source venv/bin/activate

3. **Install Dependencies**

   - Install the necessary Python packages using pip:
   ```bash
    pip3 install -r requirements.txt

4. **Run the bash backup and pam setup script:**
   ```bash
   sudo bash pam_files_backup_setup.sh

5. **Depending on your system, you need to allow port 5000 through the firewall:**

   ```bash
   # For RHEL based systems:

   sudo firewall-cmd --permanent --add-port=5000/tcp
   sudo firewall-cmd --reload
   
   #For DEBIAN based systems (like Ubuntu):

   sudo ufw allow 5000/tcp
   sudo ufw reload**

6. **Run the Application**

   - Start the Flask development server:
   ```bash
    python3.x app.py




