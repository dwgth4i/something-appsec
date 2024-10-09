const { spawn } = require("child_process");

const checkVulnerableCodeExecution = async (repoPath) => {
  return new Promise((resolve, reject) => {
    let output = '';
    let errorOutput = '';

    // Spawn the Semgrep process
    const proc = spawn('bash', ['-c', `semgrep --config "p/owasp-top-ten"`], {cwd: repoPath});

    // Collect stdout data
    proc.stdout.on('data', (chunk) => {
      output += chunk.toString();  // Collect the output data
    });

    // Collect stderr data (warnings or errors)
    proc.stderr.on('data', (chunk) => {
      errorOutput += chunk.toString();  // Collect error data
    });

    // Handle process errors
    proc.on('error', (err) => {
      reject(`Failed to run Semgrep: ${err.message}`);
    });

    // On process exit, handle the results
    proc.on('exit', (code) => {
      if (code === 0) {
        // Return the full output
        resolve(output.trim());
      } else {
        // Return stderr if there's a non-zero exit code
        reject(`Semgrep encountered an issue: ${errorOutput.trim()}`);
      }
    });
  });
};





module.exports = {
    checkVulnerableCodeExecution

};