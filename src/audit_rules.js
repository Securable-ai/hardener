async function auditRulesTemplate({ homeDir, workingDir }) {
  return `
# First rule - delete all
-D

# logs all network connections
-a exit,always -S connect -k hardener_monitored_network_connect

# logs all process executions
-a exit,always -S execve -k hardener_monitored_process_exec

# logs file changes (writes, deletes, renames, etc.)
# -a exit,always -F dir=%s -F perm=wa -S open,openat,creat,truncate,ftruncate -k file_change

-w ${homeDir} -p wa -k hardener_monitored_hardener_home_changes

-w /etc/passwd -p wa -k hardener_monitored_passwd_changes

-w /etc/shadow -p wa -k hardener_monitored_shadow_changes

-w /etc/group -p wa -k hardener_monitored_group_changes

-w /etc/sudoers -p wa -k hardener_monitored_sudoers_changes

-w /etc/sudoers.d/ -p wa -k hardener_monitored_sudoers_changes

-w /etc/docker/daemon.json -p wa -k hardener_monitored_docker_daemon_changes

-w /var/log/audit/audit.log -p wa -k hardener_monitored_audit_log_changes
`
}

module.exports = {
  auditRulesTemplate
}
