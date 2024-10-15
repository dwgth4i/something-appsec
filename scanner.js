const { spawn } = require("child_process");

const checkVulnerableCodeExecution = async (repoPath) => {
  return new Promise((resolve, reject) => {
    let output = '';
    let errorOutput = '';

    const proc = spawn('bash', ['-c', `semgrep --config "p/config-insecure"`], {cwd: repoPath});

    proc.stdout.on('data', (chunk) => {
      output += chunk.toString();
    });

    proc.stderr.on('data', (chunk) => {
      errorOutput += chunk.toString();
    });

    proc.on('error', (err) => {
      reject(`Failed to run Semgrep: ${err.message}`);
    });

    proc.on('exit', (code) => {
      if (code === 0) {
        resolve(output.trim());
      } else {
        reject(`Semgrep encountered an issue: ${errorOutput.trim()}`);
      }
    });
  });
};

// CICD-SEC-2: Inadequate Identity and Access Management
const checkIAMIssues = async (repoPath) => {
  return new Promise((resolve, reject) => {
    let output = '';
    let errorOutput = '';

    const proc = spawn('bash', ['-c', `semgrep --config "p/gitleaks"`], {cwd: repoPath});

    proc.stdout.on('data', (chunk) => {
      output += chunk.toString(); 
    });

    proc.stderr.on('data', (chunk) => {
      errorOutput += chunk.toString(); 
    });
    proc.on('error', (err) => {
      reject(`Failed to run Semgrep: ${err.message}`);
    });

    proc.on('exit', (code) => {
      if (code === 0) {
        resolve(output.trim());
      } else {
        reject(`Semgrep encountered an issue: ${errorOutput.trim()}`);
      }
    });
  });
};

// CICD-SEC-4: Poisoned Pipeline Execution
const checkPipelineConfiguration = async (repoPath) => {
  return new Promise((resolve, reject) => {
    let output = '';
    let errorOutput = '';

    const proc = spawn('bash', ['-c', `semgrep --config "p/ci"`], {cwd: repoPath});

    proc.stdout.on('data', (chunk) => {
      output += chunk.toString(); 
    });

    proc.stderr.on('data', (chunk) => {
      errorOutput += chunk.toString(); 
    });
    proc.on('error', (err) => {
      reject(`Failed to run Semgrep: ${err.message}`);
    });

    proc.on('exit', (code) => {
      if (code === 0) {
        resolve(output.trim());
      } else {
        reject(`Semgrep encountered an issue: ${errorOutput.trim()}`);
      }
    });
  });
};

module.exports = {
    checkVulnerableCodeExecution,
    checkIAMIssues,
    checkPipelineConfiguration
};