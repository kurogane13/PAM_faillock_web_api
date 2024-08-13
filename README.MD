# PAM Faillock Web API

Welcome to the PAM Faillock Web API project! This API provides a web interface for managing PAM faillock configurations and monitoring authentication logs. It is built using Flask and offers endpoints for interacting with system security settings related to account locking policies.

## Features

- **View Faillock Data**: Retrieve information on account lockout status and failed authentication attempts.
- **Update Faillock Configuration**: Modify lockout settings like unlock time and deny values.
- **Manage SSHD Service**: Start, stop, and restart the SSHD service while checking its status.
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
   git clone https://github.com/yourusername/pam-faillock-web-api.git
   cd pam-faillock-web-api

2. **Create templates folder and move index file**
   ```bash
   mkdir -p templates
   mv index.html templates

3. **Create a Virtual Environment (Recommended)**

   ```bash
    python3 -m venv venv
    source venv/bin/activate

4. **Install Dependencies**

   - Install the necessary Python packages using pip:
   ```bash
    pip3 install -r requirements.txt

5. **Run the Application**

   - Start the Flask development server:
   ```bash
    python3.x app.py




