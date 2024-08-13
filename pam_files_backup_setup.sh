#!/bin/bash

# Define the source and destination paths
declare -A files=(
    ["/etc/pam.d/system-auth"]="pam_files/system-auth"
    ["/etc/pam.d/password-auth"]="pam_files/password-auth"
    ["/etc/pam.d/sshd"]="pam_files/sshd"
    ["/etc/security/faillock.conf"]="pam_files/faillock.conf"
)

# Function to create a backup and move files
backup_and_move() {
    for dest in "${!files[@]}"; do
        src="${files[$dest]}"
        
        # Check if source file exists
        if [ -f "$src" ]; then
            # Create backup with .original extension
            echo "Backing up $dest to $dest.original"
            sudo cp "$dest" "$dest.original"
            
            # Move the file to its destination
            echo "Moving $src to $dest"
            sudo mv "$src" "$dest"
        else
            echo "Source file $src does not exist. Skipping."
        fi
    done
}

# Execute the function
backup_and_move
