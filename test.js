const fs = require('fs');

fs.readFile("/home/dwgth4i/code/Project 3/repos/1728463987326/res.json", 'utf8', (err, data) => {
    if (err) {
        return (`Error reading the gitleaks report: ${err}`);
    }
    console.log(JSON.parse(data)); // Return the content of the report
});