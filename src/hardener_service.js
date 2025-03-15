async function hardenerService(
  user,
  mode,
  allowHTTP,
  defaultPolicy,
  trustedGithubAccountsString,
  logFile,
  errorLogFile
) {
  return `
[Unit]
Description=hardener
After=network.target

[Service]
Type=simple
User=${user}
Group=${user}
ExecStart=/home/${user}/mitmdump --mode transparent --showhost --set block_global=false -s /home/${user}/intercept.py
Restart=always
Environment="hardener_MODE=${mode}"
Environment="hardener_ALLOW_HTTP=${allowHTTP}"
Environment="hardener_DEFAULT_POLICY=${defaultPolicy}"
Environment="hardener_TRUSTED_GITHUB_ACCOUNTS=${trustedGithubAccountsString}"
StandardOutput=file:${logFile}
StandardError=file:${errorLogFile}

[Install]
WantedBy=multi-user.target
`
}

module.exports = { hardenerService }
