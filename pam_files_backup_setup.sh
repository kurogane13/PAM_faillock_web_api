#!/bin/bash

# Function to back up and move files
backup_and_replace() {
    # Back up the original files
    echo "Backing up /etc/pam.d/system-auth to /etc/pam.d/system-auth.original"
    sudo cp /etc/pam.d/system-auth /etc/pam.d/system-auth.original

    echo "Backing up /etc/pam.d/password-auth to /etc/pam.d/password-auth.original"
    sudo cp /etc/pam.d/password-auth /etc/pam.d/password-auth.original

    echo "Backing up /etc/pam.d/sshd to /etc/pam.d/sshd.original"
    sudo cp /etc/pam.d/sshd /etc/pam.d/sshd.original

    echo "Backing up /etc/pam.d/gdm-password to /etc/pam.d/gdm-password.original"
    sudo cp /etc/pam.d/gdm-password /etc/pam.d/gdm-password.original

    echo "Backing up /etc/security/faillock.conf to /etc/security/faillock.conf.original"
    sudo cp /etc/security/faillock.conf /etc/security/faillock.conf.original

    # Copy the new files to their destinations
    echo "Copying pam_files/system-auth to /etc/pam.d/system-auth"
    sudo cp pam_files/system-auth /etc/pam.d/system-auth

    echo "Copying pam_files/password-auth to /etc/pam.d/password-auth"
    sudo cp pam_files/password-auth /etc/pam.d/password-auth

    echo "Copying pam_files/sshd to /etc/pam.d/sshd"
    sudo cp pam_files/sshd /etc/pam.d/sshd

    echo "Copying pam_files/gdm-password to /etc/pam.d/gdm-password"
    sudo cp pam_files/gdm-password /etc/pam.d/gdm-password

    echo "Copying pam_files/faillock.conf to /etc/security/faillock.conf"
    sudo cp pam_files/faillock.conf /etc/security/faillock.conf
}

# Execute the function
backup_and_replace
