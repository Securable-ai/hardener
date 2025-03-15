const process = require('process')
const core = require('@actions/core')
const { exec } = require('@actions/exec')
const { wait } = require('./wait')
const { hardenerService } = require('./hardener_service')
const { releaseVersion } = require('./version')
const YAML = require('yaml')
const fs = require('fs')
const {
  getMode,
  getAllowHTTP,
  getDefaultPolicy,
  getEgressRules,
  getTrustedGithubAccounts,
  getDisablePasswordlessSudo
} = require('./input')

let startTime = Date.now()

function benchmark(featureName) {
  const endTime = Date.now()
  core.info(
    `Time Elapsed in ${featureName}: ${Math.ceil((endTime - startTime) / 1000)}s`
  )
  startTime = endTime
}

/**
 * The main function for the action.
 * @returns {Promise<void>} Resolves when the action is complete.
 */
async function run() {
  try {
    startTime = Date.now()
    core.info(`Start time: ${startTime}`)

    // Set Debug mode
    const isDebugMode = process.env.DEBUG === 'true' ? 'true' : 'false'

    // pid of hardener nodejs process
    const hardenerPID = process.pid
    core.saveState('hardenerPID', hardenerPID)

    // pid of parent process - github runner process. This will spin up all other action steps
    const githubRunnerPID = process.ppid
    core.saveState('githubRunnerPID', githubRunnerPID)

    // Changing hardenerUser will require changes in hardener.service and intercept.py
    // print all folders inside /home to see if the user already exists
    await exec('ls -lah /home')
    const hardenerUser = 'hardener'
    core.saveState('hardenerUser', hardenerUser)

    const outputFile = 'output.log'
    core.saveState('outputFile', outputFile)

    const homeDir = `/home/${hardenerUser}`
    core.saveState('homeDir', homeDir)

    // Run following script before running this action
    // npm run render_ejs
    // audit script will install auditd and set up audit rules
    const { auditScriptBase64 } = require('./generated/audit-sh')
    const auditScript = Buffer.from(auditScriptBase64(), 'base64').toString()
    fs.writeFileSync('audit.sh', auditScript)

    const { auditRulesTemplate } = require('./audit_rules')

    // createhardenerUserScript will create a new user for running hardener
    const { createhardenerUserScriptBase64 } = require('./generated/create-hardener-user-sh')
    const createhardenerUserScript = Buffer.from(createhardenerUserScriptBase64(), 'base64').toString()
    fs.writeFileSync('create-hardener-user.sh', createhardenerUserScript)

    // iptablesScript will set up iptables rules
    const { iptablesScriptBase64 } = require('./generated/iptables-sh')
    const iptablesScript = Buffer.from(iptablesScriptBase64(), 'base64').toString()
    fs.writeFileSync('iptables.sh', iptablesScript)

    const mode = getMode()
    const allowHTTP = getAllowHTTP()
    const defaultPolicy = getDefaultPolicy()
    const egressRules = getEgressRules()
    const trustedGithubAccounts = getTrustedGithubAccounts()
    const disablePasswordlessSudo = getDisablePasswordlessSudo()

    const workingDir = process.env.GITHUB_WORKSPACE // e.g. /home/runner/work/hardener
    core.info(`Working directory: ${workingDir}`)
    const repoName = process.env.GITHUB_REPOSITORY // e.g. koalalab-inc/hardener
    const repoOwner = repoName.split('/')[0] // e.g. koalalab-inc

    benchmark('setup')

    core.startGroup('setup-auditd')
    core.info('Setting up auditd...')
    const auditRules = await auditRulesTemplate({ homeDir, workingDir })
    fs.writeFileSync('audit.rules', auditRules)
    await exec(`sudo bash audit.sh ${workingDir} ${isDebugMode}`)
    core.info('Setting up auditd... done')

    benchmark('setup-auditd')

    core.startGroup('create-hardener-user')
    core.info('Creating hardener user...')
    await exec(`sudo bash create-hardener-user.sh ${hardenerUser} ${isDebugMode}`)
    core.info('Creating hardener user... done')
    core.endGroup('create-hardener-user')

    benchmark('create-hardener-user')

    core.startGroup('download-executable')
    const releaseName = 'hardener'
    core.info('Downloading mitmproxy...')
    const filename = `${releaseName}-${releaseVersion}-linux-x86_64.tar.gz`
    await exec(
      `wget --quiet https://github.com/securable-ai/hardener/releases/download/${releaseVersion}/${filename}`
    )
    core.info('Downloading mitmproxy... done')
    await exec(`tar -xzf ${filename}`)
    await exec(`sudo cp hardener/mitmdump /home/${hardenerUser}/`)
    await exec(`sudo chown ${hardenerUser}:${hardenerUser} /home/${hardenerUser}/mitmdump`)
    await exec(`sudo cp hardener/intercept.py /home/${hardenerUser}/`)
    await exec(`sudo chown ${hardenerUser}:${hardenerUser} /home/${hardenerUser}/intercept.py`)
    await exec(`cp hardener/auparse ${homeDir}/auparse`)
    await exec(`chmod +x ${homeDir}/auparse`)

    await exec(`ls -lah ${homeDir}/auparse`)
    core.endGroup('download-executable')

    benchmark('download-executable')

    core.startGroup('setup-hardener')
    core.info('Reading inputs...')
    const trustedGithubAccountsString = [repoOwner, ...trustedGithubAccounts].join(',')
    const egressRulesYAML = YAML.stringify(egressRules)
    core.info('Reading inputs... done')

    core.info('Create hardener output file...')
    await exec(
      `sudo -u ${hardenerUser} -H bash -c "touch /home/${hardenerUser}/output.log`
    )
    core.info('Create hardener output file... done')

    core.info('Create hardener config...')
    const hardenerConfig = `dump_destination: "/home/${hardenerUser}/output.log"`
    fs.writeFileSync('config.yaml', hardenerConfig)
    await exec(
      `sudo -u ${hardenerUser} -H bash -c "mkdir -p /home/${hardenerUser}/.mitmproxy"`
    )
    await exec(`sudo cp config.yaml /home/${hardenerUser}/.mitmproxy/`)
    await exec(
      `sudo chown ${hardenerUser}:${hardenerUser} /home/${hardenerUser}/.mitmproxy/config.yaml`
    )
    core.info('Create hardener config... done')

    core.info('Create hardener egress_rules.yaml...')
    fs.writeFileSync('egress_rules.yaml', egressRulesYAML)
    await exec(`sudo cp egress_rules.yaml /home/${hardenerUser}/`)
    await exec(
      `sudo chown ${hardenerUser}:${hardenerUser} /home/${hardenerUser}/egress_rules.yaml`
    )
    core.info('Create hardener egress_rules.yaml... done')

    core.info('Create hardener service log files...')
    const logFile = `/home/${hardenerUser}/hardener.log`
    const errorLogFile = `/home/${hardenerUser}/hardener-error.log`
    await exec(`sudo touch ${logFile}`)
    await exec(`sudo touch ${errorLogFile}`)
    await exec(`sudo chown ${hardenerUser}:${hardenerUser} ${logFile} ${errorLogFile}`)
    core.info('Create hardener service log files... done')

    core.info('Create hardener service...')
    const hardenerServiceConfig = await hardenerService(
      hardenerUser,
      mode,
      allowHTTP,
      defaultPolicy,
      trustedGithubAccountsString,
      logFile,
      errorLogFile
    )
    fs.writeFileSync('hardener.service', hardenerServiceConfig)
    await exec('sudo cp hardener.service /etc/systemd/system/')
    await exec('sudo chown root:root /etc/systemd/system/hardener.service')
    await exec('sudo systemctl daemon-reload')
    core.info('Create hardener service... done')
    core.endGroup('setup-hardener')

    benchmark('configure-hardener')

    core.startGroup('run-hardener')
    core.info('Starting hardener...')
    await exec('sudo systemctl start hardener')
    core.info('Waiting for hardener to start...')
    await exec('sudo systemctl status hardener')
    core.info('Starting hardener... done')
    core.endGroup('run-hardener')

    benchmark('start-hardener')

    core.startGroup('trust-hardener-certificate')
    core.info('Trust hardener certificate...')
    const ms = 500
    for (let i = 1; i <= 10; i++) {
      try {
        await wait(ms)
        await exec(
          `sudo cp /home/${hardenerUser}/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/hardener.crt`
        )
        const hardenerCertDir = '/home/runner/.hardener/certs'
        const hardenerCertPath = `${hardenerCertDir}/hardener.crt`
        await exec(`mkdir -p ${hardenerCertDir}`)
        await exec(
          `sudo cp /home/${hardenerUser}/.mitmproxy/mitmproxy-ca-cert.pem ${hardenerCertPath}`
        )
        await exec(
          `sudo chown runner:runner ${hardenerCertPath}`
        )
        core.exportVariable('NODE_EXTRA_CA_CERTS', hardenerCertPath)
        await exec('sudo update-ca-certificates')
        break
      } catch (error) {
        core.info(`waiting for hardener to start, retrying in ${ms}ms...`)
      }
    }
    core.info('Trust hardener certificate... done')
    core.endGroup('trust-hardener-certificate')

    benchmark('trust-hardener-certificate')

    core.startGroup('setup-iptables-redirection')

    await exec(`sudo bash iptables.sh ${hardenerUser} ${isDebugMode}`)

    core.endGroup('setup-iptables-redirection')

    benchmark('setup-iptables-redirection')

    if (disablePasswordlessSudo) {
      core.startGroup('disable-passwordless-sudo')
      core.info('Disabling passwordless sudo...')
      await exec('sudo sed -i "/^runner/d" /etc/sudoers.d/runner')
      core.info('Disabling passwordless sudo... done')
      core.endGroup('disable-passwordless-sudo')
    }
  } catch (error) {
    // Fail the workflow run if an error occurs
    core.saveState('hardenerFailed', 'true')
    core.setFailed(error.message)
  }
}

module.exports = {
  run
}
