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

- Python 3.x
- Flask
- Flask-CORS
- `sudo` permissions for modifying system files

### Clone the Repository

```bash
git clone https://github.com/yourusername/pam-faillock-web-api.git
cd pam-faillock-web-api
