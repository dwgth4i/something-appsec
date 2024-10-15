const express = require('express');
const simpleGit = require('simple-git');
const path = require('path');
const fs = require('fs');
const bodyParser = require('body-parser');
const { exec } = require('child_process');
const util = require('util');
const { 
  checkIAMIssues,
  checkPipelineConfiguration
 } = require('./scanner');

// Initialize Express app
const app = express();
const git = simpleGit();

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Serve static files from the "public" folder
app.use(express.static(path.join(__dirname, 'public')));

// Directory to store cloned repositories
const REPO_DIR = path.join(__dirname, 'repos');

// Ensure the repos directory exists
if (!fs.existsSync(REPO_DIR)) {
  fs.mkdirSync(REPO_DIR);
}

// Route to clone a repository
app.post('/clone-repo', async (req, res) => {
  const { repoUrl } = req.body;
  const parsedUrl = new URL(repoUrl);
  const repoName = path.basename(parsedUrl.pathname, '.git');
  const repoPath = path.join(REPO_DIR, repoName);

  try {
    if (fs.existsSync(repoPath)) {
      return res.status(400).json({ error: `Repository "${repoName}" already exists.` });
    }

    console.log(`Cloning repo from ${repoUrl} to ${repoPath}`);
    await git.clone(repoUrl, repoPath);
    console.log(`Cloned repo to ${repoPath}`);

    res.json({ message: `Repository "${repoName}" cloned successfully.` });
  } catch (err) {
    console.error('Failed to clone repo:', err);
    res.status(500).json({ error: 'Failed to clone repository.' });
  }
});

// Route to list all cloned repositories
app.get('/list-repos', (req, res) => {
  fs.readdir(REPO_DIR, (err, files) => {
    if (err) {
      console.error('Failed to list repos:', err);
      return res.status(500).json({ error: 'Failed to list repositories.' });
    }
    res.json(files);
  });
});

// Route to delete a repository
app.delete('/delete-repo/:repoName', (req, res) => {
  const { repoName } = req.params;
  const repoPath = path.join(REPO_DIR, repoName);

  if (!fs.existsSync(repoPath)) {
    return res.status(404).json({ error: `Repository "${repoName}" not found.` });
  }

  fs.rm(repoPath, { recursive: true, force: true }, (err) => {
    if (err) {
      console.error('Failed to delete repo:', err);
      return res.status(500).json({ error: 'Failed to delete repository.' });
    }
    res.json({ message: `Repository "${repoName}" has been deleted.` });
  });
});

// Route to serve the scan form
app.get('/scan/:repoName', (req, res) => {
  const { repoName } = req.params;
  const repoPath = path.join(REPO_DIR, repoName);

  if (!fs.existsSync(repoPath)) {
    return res.status(404).send(`Repository "${repoName}" not found.`);
  }

  res.sendFile(path.join(__dirname, 'public', 'scan.html'));
});

// Route to handle the scan submission
app.post('/scan/:repoName', async (req, res) => {
  const { repoName } = req.params;
  const { risks } = req.body;

  const repoPath = path.join(REPO_DIR, repoName);

  if (!fs.existsSync(repoPath)) {
    return res.status(404).json({ error: `Repository "${repoName}" not found.` });
  }

  const scanResults = {};

  try {
    for (const risk of risks) {
      switch (risk) {
        case 'Insecure Configuration':
          scanResults[risk] = await checkInsecureConfiguration(repoPath);
          break;
        case 'Insufficient IAM':
          scanResults[risk] = await checkIAMIssues(repoPath);
          break;
        case 'Insecure Secrets Management':
          scanResults[risk] = await checkSecretsManagement(repoPath);
          break;
        case 'Improper Artifact Integrity':
          scanResults[risk] = await checkArtifactIntegrity(repoPath);
          break;
        case 'Insufficient Flow Control Mechanisms':
          scanResults[risk] = await checkFlowControlMechanisms(repoPath);
          break;
        case 'Insufficient Verification of Dependencies':
          scanResults[risk] = await checkSnykDependencies(repoPath);
          break;
        case 'Untrusted Artifact Downloads':
          scanResults[risk] = await checkUntrustedArtifactDownloads(repoPath);
          break;
        case 'Insecure Pipeline Configuration':
          scanResults[risk] = await checkPipelineConfiguration(repoPath);
          break;
        case 'Insecure System Configuration':
          const checkovResult = await checkIaCSecurityWithCheckov(repoPath);
          const tfsecResult = await checkTerraformWithTfsec(repoPath);
          scanResults[risk] = `${checkovResult}; ${tfsecResult}`;
          break;
        case 'Insufficient Logging and Monitoring':
          const semgrepLogging = await checkLoggingAndMonitoring(repoPath);
          const loggingConfigs = await verifyLoggingConfigurations(repoPath);
          scanResults[risk] = `${semgrepLogging}; ${loggingConfigs}`;
          break;
        default:
          scanResults[risk] = 'Unknown risk type.';
      }
    }

    res.json({
      repo: repoName,
      results: scanResults,
      message: `Scan completed for "${repoName}".`
    });
  } catch (err) {
    console.error('Error during scanning:', err);
    res.status(500).json({ error: `Error scanning repository: ${err}` });
  }
});

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
