const express = require('express');
const simpleGit = require('simple-git');
const path = require('path');
const fs = require('fs');
const bodyParser = require('body-parser');
const { checkVulnerableCodeExecution } = require('./scanner');


// Initialize Express and Git app
const app = express();
const git = simpleGit();
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));


// Directory to store cloned repositories
const REPO_DIR = path.join(__dirname, 'repos');

// Ensure the repos directory exists
if (!fs.existsSync(REPO_DIR)) {
  fs.mkdirSync(REPO_DIR);
}

app.get('/list-repos', (req, res) => {
    fs.readdir(REPO_DIR, (err, files) => {
      if (err) {
        return res.status(500).json({ error: 'Failed to list repositories' });
      }
      // Send the list of repo directories
      res.json(files);
    });
  });

app.post('/clone-repo', async (req, res) => {
  const { repoUrl } = req.body;
  const timestamp = new Date().getTime().toString()
  const repoDir = path.join(__dirname, 'repos', timestamp);
  
  try {
    await git.clone(repoUrl, repoDir);
    res.json({ message: `Repository - ${repoUrl} cloned to /repos/${timestamp}` });
  } catch (err) {
    console.error('Failed to clone repo:', err);
    res.status(500).json({ error: 'Failed to clone repository' });
  }
});

// Route to serve the scan form for a specific repository
app.get('/scan/:repoName', (req, res) => {
  const { repoName } = req.params;
  const repoPath = path.join(REPO_DIR, repoName);

  if (!fs.existsSync(repoPath)) {
    return res.status(404).json({ error: `Repository ${repoName} not found.` });
  }

  // Serve the scan.html file
  res.sendFile(path.join(__dirname, 'public', 'scan.html'));
});

// Route to handle the form submission for scanning a repository
app.post('/scan/:repoName', async (req, res) => {
  const { repoName } = req.params;
  const { risks } = req.body;

  const repoPath = path.join(REPO_DIR, repoName);

  if (!fs.existsSync(repoPath)) {
    return res.status(404).json({ error: `Repository ${repoName} not found.` });
  }

  const scanResults = {};

  try {
    // Use a for-loop to ensure that each scan completes before proceeding to the next one
    for (const risk of risks) {
      switch (risk) {
        case 'Insecure Dependencies':
          scanResults[risk] = await checkInsecureDependencies(repoPath);
          break;
        case 'Secrets Management Failures':
          scanResults[risk] = await checkSecretsManagement(repoPath);
          break;
        case 'Improper Artifact Integrity':
          scanResults[risk] = await checkArtifactIntegrity(repoPath);
          break;
        case 'Weak Credentials':
          scanResults[risk] = await checkWeakCredentials(repoPath);
          break;
        case 'Vulnerable Code':
          scanResults[risk] = await checkVulnerableCodeExecution(repoPath);  // Ensure this awaits properly
          console.log(scanResults)
          break;
        default:
          scanResults[risk] = 'Unknown risk type.';
      }
    }

    // Only send the response after all scans have completed
    res.json({
      repo: repoName,
      results: scanResults,
      message: `Scan completed for ${repoName}: ${JSON.stringify(scanResults)}`
    });
  } catch (err) {
    // Handle any errors from the scanning process
    res.status(500).json({ error: `Error scanning repository: ${err}` });
  }
});

app.delete('/delete-repo/:repoName', (req, res) => {
    const { repoName } = req.params;
    const repoPath = path.join(REPO_DIR, repoName);
  
    if (!fs.existsSync(repoPath)) {
      return res.status(404).json({ error: `Repository ${repoName} not found.` });
    }
  
    // Remove the repository folder
    fs.rm(repoPath, { recursive: true, force: true }, (err) => {
      if (err) {
        console.error('Failed to delete repo:', err);
        return res.status(500).json({ error: 'Failed to delete repository' });
      }
      res.json({ message: `Repository ${repoName} has been deleted.` });
    });
  });

// Start the server
const PORT = 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
