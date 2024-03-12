#!/bin/bash

backup_dir="$HOME/Desktop/sysconfig_backups"

# Function to restore a backup file
restore_backup() {
    local file=$1
    local backup_file="$backup_dir/$(basename $file).backup"

    if [ -f $backup_file ]; then
        cp $backup_file $file
        echo "Restored backup: $file"

        # Check if the file corresponds to a service configuration
        case "$file" in
            "/etc/ssh/sshd_config")
                systemctl restart ssh
                ;;
            "/etc/apache2/conf-enabled/security.conf")
                systemctl restart apache2
                ;;

            "/etc/audit/rules.d/audit.rules")
                systemctl restart auditd
                ;;
            "/etc/sysctl.conf")
                sysctl -p
                ;;
            # Add more cases for other services as needed
        esac
    else
        echo "Backup not found: $backup_file"
    fi
}

# Restore original files
restore_backup "/etc/login.defs"
restore_backup "/etc/ssh/sshd_config"
restore_backup "/etc/apache2/conf-enabled/security.conf"
restore_backup "/etc/security/pwquality.conf"
restore_backup "/etc/fstab"
restore_backup "/etc/sudoers"
restore_backup "/etc/audit/rules.d/audit.rules"
restore_backup "/etc/sysctl.conf"

echo "Backup restoration completed successfully."
