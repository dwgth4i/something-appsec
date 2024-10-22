const { spawn } = require("child_process");
const fs = require('fs');
const path = require('path');

// CICD-SEC-1: Insufficent Flow Control Mechanism
async function checkFlowControlMechanisms(repoPath) {
  return new Promise((resolve, reject) => {
      const outputFilePath = path.join(__dirname, 'public', 'checkov_output');
      const proc = spawn('checkov', ['--directory', repoPath, '--output-file-path', outputFilePath], {
          shell: true
      });

      let output = '';
      let errorOutput = '';

      // Capture stdout
      proc.stdout.on('data', (chunk) => {
          output += chunk.toString();
      });

      // Capture stderr
      proc.stderr.on('data', (chunk) => {
          errorOutput += chunk.toString();
          console.error('Error:', chunk.toString());
      });

      proc.on('error', (err) => {
          reject(err);
      });

      proc.on('exit', (code) => {
          if (code === 0) {  
              const terraformSummary = extractCheckovSummary(output, 'terraform');
              const githubActionsSummary = extractCheckovSummary(output, 'github_actions');

              if (terraformSummary || githubActionsSummary) {
                  let result = '';

                  if (terraformSummary) {
                      result += `Terraform scan results:\n${terraformSummary}\n\n`;
                  }
                  if (githubActionsSummary) {
                      result += `GitHub Actions scan results:\n${githubActionsSummary}\n\n`;
                  }

                  result += `Details: The saved output file path is: ${outputFilePath}`;

                  resolve(result.trim());
              } else {
                  resolve('No scan results found.');
              }
          } else {
              reject(new Error(`Checkov scan exited with code ${code}.\n${errorOutput}`));
          }
      });
  });
}

// Helper function to extract scan summary
function extractCheckovSummary(output, scanType) {
  const startMarker = `${scanType} scan results:`;
  const endMarker = 'Details:';

  const startIndex = output.indexOf(startMarker);
  const endIndex = output.indexOf(endMarker, startIndex);

  if (startIndex !== -1 && endIndex !== -1) {
      return output.substring(startIndex, endIndex).trim();
  } else {
      // In case the summary isn't found as expected, return null.
      return null;
  }
}
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

// CIDE-SEC-3: 
async function checkDependencyChainAbuse(repoPath) {
  return new Promise((resolve, reject) => {
      const proc = spawn('safety', ['scan', '.'], {
          cwd: repoPath,
          shell: true
      });

      let output = '';
      let errorOutput = '';

      // Handle stdout
      proc.stdout.on('data', (chunk) => {
          output += chunk.toString();
      });

      // Handle stderr
      proc.stderr.on('data', (chunk) => {
          errorOutput += chunk.toString();
          console.error('Error:', chunk.toString());
      });

      proc.on('error', (err) => {
          reject(err);
      });

      proc.on('exit', (code) => {
          if (code === 64) { // 0 means success
              // Look for the vulnerability section in the output
              const startMarker = 'Dependency vulnerabilities detected:';
              const endMarker = 'Apply Fixes';

              // Find the start and end positions
              const startIndex = output.indexOf(startMarker);
              const endIndex = output.indexOf(endMarker);

              if (startIndex !== -1 && endIndex !== -1) {
                  const vulnerabilitiesSection = output.substring(startIndex, endIndex).trim();
                  resolve(vulnerabilitiesSection);
              } else {
                  resolve('No vulnerabilities found.');
              }
          } else if (code === 0) {
            resolve("No issues found.")
          } else {
              reject(new Error(`Safety check exited with code ${code}.\n${errorOutput}`));
          }
      });
  });
}

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

// CICD-SEC-6: Insufficient Credential Hygiene
async function checkCredentialHygiene(repoPath) {
  const outputFile = path.join(repoPath, 'sec6.txt'); // Specify the output file path

  return new Promise((resolve, reject) => {
      // Run gitleaks command
      const proc = spawn('/home/dwgth4i/tools/gitleaks/gitleaks', ['detect', '-v', '-s', repoPath, '-r', outputFile]);

      // Handle stdout and stderr
      proc.stdout.on('data', (chunk) => {
          console.log(chunk.toString());
      });

      proc.stderr.on('data', (chunk) => {
          console.error('Error:', chunk.toString());
      });

      proc.on('error', (err) => {
          reject(err);
      });

      proc.on('exit', (code) => {
          if (code === 0) {
              // Read the output file after the scan completes
              fs.readFile(outputFile, 'utf8', (err, data) => {
                  if (err) {
                      return reject(err);
                  }
                  resolve(data); // Parse the JSON result
              });
          } else if (code === 1) {
              // If gitleaks found leaks, still resolve the result
              fs.readFile(outputFile, 'utf8', (err, data) => {
                  if (err) {
                      return reject(err);
                  }
                  resolve(data); // Parse the JSON result, even if leaks were found
              });
          } else {
              reject(new Error(`Gitleaks exited with code ${code}`));
          }
      });
  });
}

module.exports = {
    checkIAMIssues,
    checkCredentialHygiene,
    checkDependencyChainAbuse
};