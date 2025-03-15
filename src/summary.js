const core = require('@actions/core')
const { DefaultArtifactClient } = require('@actions/artifact')
const { exec } = require('@actions/exec')
const { getAuditSummary, checkForBuildTampering } = require('./audit_summary')
const fs = require('fs')
const YAML = require('yaml')
const {
  getMode,
  getAllowHTTP,
  getDefaultPolicy,
  getEgressRules,
  getTrustedGithubAccounts,
  getEndPoint,
  getAPIKey
} = require('./input')
const {
  generateTestResults,
  getGithubCalls,
  getUniqueBy,
  getRawCollapsible
} = require('./summary_utils')

// Configuration and Inputs
const mode = getMode()
const allowHTTP = getAllowHTTP()
const defaultPolicy = getDefaultPolicy()
const egressRules = getEgressRules()
const trustedGithubAccounts = getTrustedGithubAccounts()
const repoName = process.env.GITHUB_REPOSITORY // e.g., securable-ai/hardener
const repoOwner = repoName.split('/')[0] // e.g., securable-ai

// Helper function to generate action icons and labels
function actionString(action) {
  switch (action) {
    case 'block':
      return mode === 'active'
        ? '⛔ Blocked'
        : '⚠️ Will be blocked in Active mode'
    case 'allow':
      return '✅ Allowed'
    default:
      return '❓ Unknown'
  }
}

// Convert result to a table row
function resultToRow(result) {
  return [
    result.destination,
    result.scheme,
    result.rule_name,
    actionString(result.action)
  ]
}

// Main function to generate the summary report
async function generateSummary() {
  const isDebugMode = process.env.DEBUG === 'true'
  const outputFile = core.getState('outputFile')
  const homeDir = core.getState('homeDir')
  const hardenerUser = core.getState('hardenerUser')

  const egressRulesYAML = YAML.stringify(egressRules)

  const artifactClient = new DefaultArtifactClient()

  const jobID = process.env.GITHUB_JOB
  const runId = process.env.GITHUB_RUN_ID
  const runNumber = process.env.GITHUB_RUN_NUMBER
  const runAttempt = process.env.GITHUB_RUN_ATTEMPT
  const randomString = Math.random().toString(36).substring(7)
  const jobName = `${jobID}-${runId}-${runAttempt}-${runNumber}-${randomString}`

  const githubCallsFilename = `${homeDir}/github_calls.json`

  // Debug mode: Upload audit logs
  if (isDebugMode) {
    const artifactName = `${jobName}-hardener-auditd-log`
    const files = ['/var/log/audit/audit.log']

    const { id, size } = await artifactClient.uploadArtifact(
      artifactName,
      files,
      '/var/log/audit'
    )
    core.info(
      `Created hardener auditd log artifact with id: ${id} (bytes: ${size})`
    )
  }

  // Parse audit logs
  await exec(
    `${homeDir}/auparse -format=json -i -out audit.json -in /var/log/audit/audit.log`
  )
  await artifactClient.uploadArtifact(
    `${jobName}-hardener-audit-json`,
    ['audit.json'],
    process.cwd()
  )

  // Validate required files and state
  if (!outputFile || !hardenerUser || !homeDir) {
    core.info('Invalid Bold run. Missing required state variables')
    return
  }
  if (!fs.existsSync(`${homeDir}/${outputFile}`)) {
    core.info('Hardener output file not found')
    return
  }

  await exec(`cp ${homeDir}/${outputFile} ${outputFile}`)

  const results = await generateTestResults(outputFile)
  const githubCalls = getGithubCalls(githubCallsFilename)

  const uniqueResults = getUniqueBy(results, ['destination', 'scheme'])

  // Process GitHub account calls
  const githubAccounts = githubCalls.reduce((accounts, call) => {
    const path = call.path
    const method = call.method
    let name = ''
    if (path.startsWith('/orgs/') || path.startsWith('/repos/')) {
      const parts = path.split('/')
      name = parts[2]
    }

    const trusted_flag =
      trustedGithubAccounts.includes(name) || name === repoOwner
    accounts[name] = accounts[name] || {}
    accounts[name].name = name
    accounts[name].trusted = trusted_flag
    const paths = accounts[name].paths || []
    if (!paths.some(p => p.path === path)) {
      accounts[name].paths = [...paths, { path, method }]
    }
    return accounts
  }, {})

  const untrustedGithubAccounts = Object.values(githubAccounts).filter(
    account => !account.trusted
  )

  // Configuration map and table
  const configMap = { mode, allowHTTP, defaultPolicy }
  const configTable = [
    ['Mode', mode],
    ['Allow HTTP', `${allowHTTP}`],
    ['Default Policy', defaultPolicy]
  ]

  // Known and unknown destinations tables
  const knownDestinations = [
    [
      { data: 'Destination', header: true },
      { data: 'Scheme', header: true },
      { data: 'Rule', header: true },
      { data: 'Action', header: true }
    ],
    ...uniqueResults
      .filter(result => result.default || result.action === 'allow')
      .map(resultToRow)
  ]

  const unknownDestinations = [
    [
      { data: 'Destination', header: true },
      { data: 'Scheme', header: true },
      { data: 'Rule', header: true },
      { data: 'Action', header: true }
    ],
    ...uniqueResults
      .filter(result => result.default === false && result.action === 'block')
      .map(resultToRow)
  ]

  // Trusted GitHub accounts table
  const trustedGithubAccountsData = [
    [{ data: 'GitHub Account', header: true }],
    ...trustedGithubAccounts.map(account => [account])
  ]

  // Log configuration and results
  core.info('securable-ai-hardener-config>>>')
  core.info(JSON.stringify(configMap))
  core.info('<<<securable-ai-hardener-config')
  try {
    core.info('securable-ai-hardener-egress-config>>>')
    core.info(JSON.stringify(egressRules))
    core.info('<<<securable-ai-hardener-egress-config')
  } catch (error) {
    core.info(`Invalid YAML: ${error.message}`)
  }
  core.info('securable-ai-hardener-egress-traffic-report>>>')
  core.info(JSON.stringify(results))
  core.info('<<<securable-ai-hardener-egress-traffic-report')

  // Generate summary sections
  const configHeaderString = core.summary
    .addHeading('⚙️ Hardener Configuration', 3)
    .stringify()
  core.summary.emptyBuffer()

  const configTableString = core.summary.addTable(configTable).stringify()
  core.summary.emptyBuffer()

  const trustedGithubAccountsHeaderString = core.summary
    .addHeading('🔐 Trusted GitHub Accounts', 4)
    .stringify()
  core.summary.emptyBuffer()

  const trustedGithubAccountsTableString = core.summary
    .addTable(trustedGithubAccountsData)
    .stringify()
  core.summary.emptyBuffer()

  const knownDestinationsHeaderString = core.summary
    .addHeading('🌐 Known Destinations', 4)
    .stringify()
  core.summary.emptyBuffer()

  const knownDestinationsTableString = core.summary
    .addTable(knownDestinations)
    .stringify()
  core.summary.emptyBuffer()

  const unknownDestinationsHeaderString = core.summary
    .addHeading('🚩 Unknown Destinations', 4)
    .stringify()
  core.summary.emptyBuffer()

  const unknownDestinationsTableString = core.summary
    .addTable(unknownDestinations)
    .stringify()
  core.summary.emptyBuffer()

  const auditSummary = await getAuditSummary()
  const tamperedFiles = (await checkForBuildTampering()) || []

  const tamperedFilesData = [
    [{ data: 'Tampered Files', header: true }],
    ...tamperedFiles.map(file => [file])
  ]

  const auditSummaryRaw = auditSummary.zeroState
    ? auditSummary.zeroState
    : getRawCollapsible(auditSummary)

  // Build the final summary
  let summary = core.summary
    .addSeparator()
    .addEOL()
    .addHeading(
      '📊 Github Actions Security Report - Powered by Securable.ai Hardener',
      2
    )
    .addRaw(
      `
<details open>
  <summary>
${configHeaderString}
  </summary>
${configTableString}
</details>
    `
    )

  if (trustedGithubAccounts.length > 0) {
    summary = summary
      .addRaw(
        `
<details open>
  <summary>
    ${trustedGithubAccountsHeaderString}
  </summary>
  ${trustedGithubAccountsTableString}
</details>
        `
      )
      .addQuote(
        'NOTE: The account in which the workflow runs is always trusted.'
      )
  }

  if (egressRules.length > 0) {
    summary = summary
      .addHeading('📜 Outbound Access Rules', 3)
      .addCodeBlock(egressRulesYAML, 'yaml')
  } else {
    summary = summary
      .addRaw(
        `
> [!NOTE]
> You have not configured outbound access rules. Only the default policy will be applied. See [documentation](https://github.com/securable-ai/hardener/blob/main/README.md#custom-egress-policy) for more information.
      `
      )
      .addEOL()
  }

  if (untrustedGithubAccounts.length > 0) {
    summary = summary.addHeading(
      '🚨 Requests to Untrusted GitHub Accounts Found',
      3
    ).addRaw(`
  > [!CAUTION]
  > If you do not recognize these GitHub accounts, investigate further. Add them to your trusted GitHub accounts if this is expected. See [Docs](https://github.com/securable-ai/hardener?tab=readme-ov-file#configure) for more information.
        `)

    for (const account of untrustedGithubAccounts) {
      summary = summary.addRaw(`
  <details open>
    <summary>
      ${account.name}
    </summary>
    <ul>
      ${account.paths.map(({ method, path }) => `<li><b>[${method}]</b> ${path}</li>`).join('')}
    </ul>
  </details>
          `)
    }
  }

  if (tamperedFiles.length > 0) {
    summary = summary.addHeading('🚨 File Tampering Detected', 3).addRaw(`
  > [!CAUTION]
  > Source files were edited after being fetched from the repository. This may be a security risk. Investigate further.
        `)

    summary = summary.addTable(tamperedFilesData)
  }

  summary = summary.addRaw(auditSummaryRaw)

  summary = summary.addHeading('🌍 Outbound Traffic Overview', 3)

  if (mode === 'active') {
    summary = summary.addQuote(
      'NOTE: Running in Active mode. All unknown/unverified destinations will be blocked.'
    )
  } else {
    summary = summary.addQuote(
      'NOTE: Running in Audit mode. Unknown/unverified destinations will be blocked in Active mode.'
    )
  }

  summary = summary
    .addRaw(
      `
<details open>
  <summary>
${unknownDestinationsHeaderString}
  </summary>
${unknownDestinationsTableString}
</details>
    `
    )
    .addRaw(
      `
<details open>
  <summary>
${knownDestinationsHeaderString}
  </summary>
${knownDestinationsTableString}
</details>
    `
    )
    .addLink(
      'View detailed analysis of this run on Securable!',
      'https://www.securable.ai'
    )
    .addSeparator()

  // Write the summary
  summary.write()
  core.info('Summary generated')

  const endPoint = getEndPoint()
  const apiKey = getAPIKey()
  core.info(`Endpoint: ${endPoint}`)
  core.info(`API Key: ${apiKey}`)
  if (endPoint != '' && apiKey != '') {
    core.info('Sending summary to API endpoint')
    const reportData = {
      metadata: {
        repo: repoName,
        run_id: runId,
        job_id: jobID,
        mode: mode,
        timestamp: new Date().toISOString()
      },
      configuration: {
        allow_http: allowHTTP,
        default_policy: defaultPolicy,
        trusted_github_accounts: trustedGithubAccounts,
        egress_rules: egressRules
      },
      results: {
        total_requests: results.length,
        unique_destinations: uniqueResults.length,
        allowed_requests: results.filter(r => r.action === 'allow').length,
        blocked_requests: results.filter(r => r.action === 'block').length,
        destinations: uniqueResults.map(result => ({
          destination: result.destination,
          scheme: result.scheme,
          rule: result.rule_name,
          action: result.action
        }))
      },
      security_findings: {
        untrusted_github_accounts: untrustedGithubAccounts,
        tampered_files: tamperedFiles,
        audit_summary: {
          total_events: auditSummary.total,
          suspicious_processes: auditSummary.suspiciousProcesses,
          suspicious_files: auditSummary.suspiciousFiles,
          network_events: auditSummary.networkEvents
        }
      },
      raw_data: {
        github_calls: githubCalls,
        audit_logs: auditSummary.rawLogs // Assuming auditSummary contains raw logs
      }
    }
    const response = await fetch(endPoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application',
        Authorization: `Bearer ${apiKey}`
      },
      body: JSON.stringify({
        summary: JSON.stringify(reportData)
      })
    })
    core.info(`API response: ${response.status}`)
  } else {
    core.info(
      'API endpoint or API key not provided, skipping Sending summary to API endpoint'
    )
  }
}

module.exports = { generateSummary }
