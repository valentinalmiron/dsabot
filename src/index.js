// Import modules
import express from "express";
import { exec } from "child_process";
import fs from 'fs';
import dotenv from 'dotenv';
import axios from 'axios';
import FormData from 'form-data';
import { getParametersData } from './lib/getParametersData.js';
import { getWebhookData } from './lib/getWebhookData.js';
import * as validate from './lib/validateRequests.js';

// Load environment variables
dotenv.config({ path: './.env' });

// Initialize Express app
const app = express();
const param=getParametersData();

// Function to verify JSON format
function jsonVerify(req, res, buf) {
  try {
    JSON.parse(buf);
  } catch (err) {
    return res.status(400).send({ error: 'DEBUG:ERR:RCV: Invalid JSON format: ' + buf });
  }
}

// Use JSON middleware
app.use(express.json({ verify: jsonVerify }));

// root endpoint '/'
app.get('/',(req,res) => {
  res.send(`InfoSec Tool - Bot NodeJS App:
    /webhook [POST]: Receive GitHub json file from Webhook
    /:org/repos [GET]: Save Organizaction repositories in json file.
    /:org/:repo/:branch/sbom [GET]: Generate SBOM file for the Org, Repo.`);
})

// status endpoint 'status'
app.get('/status',(req,res) => {
   res.status(200).send('The process was completed');
})

//  Do the SCA process for the repo and branch
app.get('/:org/:repo/:branch/sbom', (req, res) => {
  const data = {
    organization: req.params.org,
    nameRepository: req.params.repo,
    base: req.params.branch,
    number:'0.0.0',
    urlRepository:`https://github.com/${req.params.org}/${req.params.repo}`
  };
  data.sbomLocalFileName = `temp/my_sbom_files/${param.BOM_PREFIX_FILE}${data.nameRepository}${param.STR_SEPARATOR}${data.number}${param.JSON_EXTENSION}`;

  createSBOM(data)
  .then((stdout) => {
    console.log(stdout);

    data.sbomFileName = `${param.BOM_PREFIX_FILE}${data.nameRepository}${param.JSON_EXTENSION}`;
    const fileContent = readSBOMFile(data.sbomLocalFileName);
    dependencyTrackIngest(param, data, fileContent)
    .then(response => {
      param.APP_DEBUG=='true' ? console.log(`DEBUG:INFO:DTR: D. Track ingested ${JSON.stringify(response)}`) : null;
      console.log(response);
      return res.status(200).send(`Process completed`);
    })
    .catch((err) => {
      console.log(err);
      process.exit(1);
    })  
  })
  .catch(error => {
    console.log(error);
    return res.status(400).send('Process failed');
  }); 
}); 

//  Get all repositories in the organization
app.get('/:org/repos', async (req,res) => {
  try {
    let organization=req.params.org;
    const apiUrl = `https://api.github.com/orgs/${organization}/repos?per_page=100`;
    const token = process.env.GITHUB_TOKEN;
    let allRepositories = [];
  
    function parseLinkHeader(linkHeader) {
      const links = {};
      if (linkHeader) {
        linkHeader.split(',').forEach(link => {
          const parts = link.split(';');
          const url = parts[0].trim().slice(1, -1);
          const name = parts[1].trim().slice(5, -1);
          links[name] = { url };
        });
      }
      return links;
    }

    async function getRepositories (url) {
      try {
        const response = await axios.get(url, {
          headers: {
            'Authorization': `Token ${token}`,
            'User-Agent': 'MyGithubApp',
            'Accept': 'application/vnd.github+json'
          }
        });

        if (response.status >= 400) {
          console.error(response.data);
        } else {
          console.log (response.data)
          const repositories = response.data;
          repositories.forEach(repository => {
            allRepositories.push({
              "action": repository.action,
              "pull_request": {
                "state": repository.state,
                "base": {
                  "ref": repository.default_branch,
                },
              },
              "merged": repository.merged,
              "repository": {
                "name": repository.name,
                "html_url": repository.html_url,
                "archived" : repository.archived,
                "disabled" : repository.disabled,
                "visibility" : repository.visibility,
                "default_branch:" : repository.default_branch
              }
            });
          });          

          // Check if there's another page of results
          const links = parseLinkHeader(response.headers.link);
          if (links.next) {
            await getRepositories(links.next.url);
            console.log("url: "+links.next.url);
          } 
        }
      } catch (error) {
        console.error(error);
      }
    }                                      

    await getRepositories(apiUrl);

    let jsonRepos=JSON.stringify(allRepositories,null,2);
    let nameOrgFile='temp/my_sbom_files/'+organization.concat(param.JSON_EXTENSION);
    fs.writeFile(nameOrgFile, jsonRepos, 'utf8', function (err) {
      if (err) {
        param.APP_DEBUG == 'true' ? console.log(`DEBUG:ERR:WRCV: An error occured while writing Repositories GitHub to File. ${err}`): null;
      } else {
        param.APP_DEBUG == 'true' ? console.log(`DEBUG:SUCCESS:WRCV: Repositories GitHub file has been saved: ${organization}${param.JSON_EXTENSION}`):null;
      }
    });
  } catch (err) {
    param.APP_DEBUG == 'true' ? console.log("DEBUG:ERR:WRCV:Catched: An error occured while writing Repositories GitHub to File.") : null;
  }
  res.status(200).send('The process was completed');
});

// Save JSON payload to local disk -> func(fileName, jsonContent)
function writePayloadToJsonFile( fileName, jsonDataStr) {
    try {
      fs.writeFile(fileName, jsonDataStr, 'utf8', function (err) {
        if (err) {
          param.APP_DEBUG=='true' ? console.log(`DEBUG:ERR:WRCV: An error occured while writing GitHub JSON Object to File. ${err}`) : null;
        }
        param.APP_DEBUG=='true' ? console.log(`status: 200, message: DEBUG:SUCCESS:WRCV: GitHub JSON file has been saved. `) : null;
      });
    } catch (err) {
      param.APP_DEBUG=='true' ? console.log("DEBUG:ERR:WRCV: Catched: An error occured while writing GitHub JSON Object to File.") : null;  
    }
}

// Create SBOM file from BOM tool defined
async function createSBOM(data) {
  const nameBranch = `--branch ${data.base}`;
  const filePath=`${param.CMD_SBOM}${data.sbomLocalFileName}`
  const sbomCommand = `${filePath} ${data.urlRepository} ${nameBranch}`;
  param.APP_DEBUG=='true' ? console.log(sbomCommand) : null;

  const CMD_SBOM_TIMEOUT=param.CMD_SBOM_TIMEOUT;
  param.APP_DEBUG=='true' ? console.log(`DEBUG:INFO:BOM: ${new Date()} Executing SBOM tool - generating SBOM file..`) : null;

  return await new Promise((resolve, reject) => {

    exec(sbomCommand, { CMD_SBOM_TIMEOUT }, (err, stdout, stderr) => {
      if (err) {
        reject(new Error(`BOM Execute ${sbomCommand} generate catched error: ${err}-${stderr}`));
      } else {
        param.APP_DEBUG=='true' ? console.log(`DEBUG:SUCCESS:BOM: BOM file created succesfully`) : null;

        const fileSizeInBytes = fs.statSync(data.sbomLocalFileName).size;
        const result = { status: 200, message: `INFO:SUCCESS:BOM: ${new Date()} SBOM file created ${data.sbomLocalFileName} ${stdout} - File Size: ${fileSizeInBytes} bytes` };
        const jsonResult = JSON.stringify(result);
        resolve (jsonResult);
      }
    });
  });
}

// Remove SBOM file created from BOM tool defined
function removeSBOM(data) {
  fs.unlink(data.sbomLocalFileName, () => {
    return true;
  });
}

// Read SBOM file created from BOM tool defined
function readSBOMFile(sbomLocalFileName) {
    let fileContent;
    try {
      fileContent = fs.readFileSync(sbomLocalFileName);
      param.APP_DEBUG=='true' ? console.log(`DEBUG:SUCCESS:BOM: BOM Read succesfully`):null;
    } catch (err) {
      param.APP_DEBUG=='true' ? console.log(`DEBUG:ERR:BOM: BOM Read generate the following error: ${err}`):null;
    }
    return fileContent;
}

async function dependencyTrackIngest(param, data, fileContent) {
  param.APP_DEBUG=='true' ? console.log(`DEBUG:INFO:DTR: D. Track URL path: ${param.DTRACK_API_URL} ingesting..`) : null;

  // Begin section Ingest into Dependency Track using Axios
  let formData = new FormData();
  formData.append('autoCreate', 'true');
  formData.append('projectName', data.nameRepository);
  formData.append('projectVersion', data.base);
  formData.append('bom', fileContent);

  let optionsDTrack = {
    method: 'post',
    maxBodyLength: Infinity,
    url: param.DTRACK_API_URL,
    headers: {
      'Content-Type': 'multipart/form-data',
      'Accept': 'application/json',
      'X-Api-Key': param.DTRACK_API_KEY
    },
    data: formData
  }; 
  
  //  Promise was needed because s3.upload is Async.
  try {
    const response = await axios.request(optionsDTrack);
    // Ingest the file into D.Track
    const result = {
      status: response.status,
      message: `INFO:SUCCESS:DTR: ${new Date()} ${data.nameRepository} ingested into D.Track.`,
      responseData: response.data
    };
    const jsonResult = JSON.stringify(result);
    return jsonResult;
  } catch (error) {
    let result_2;
    if (error.response) {
      result_2 = {
        status: error.response.status,
        message: `DEBUG:ERR:DTR:  ${new Date()} Ingest ${data.nameRepository} in D.Track generate the following error: ${error.response.data}`
      };
    } else {
      result_2 = {
        message: `DEBUG:ERR:DTR:  ${new Date()} Ingest ${data.nameRepository} in D.Track generate the following error: ${error.message}`
      };
    }
    const jsonResult_1 = JSON.stringify(result_2);
    return (jsonResult_1);
  }
}
 
app.post('/webhook', function (req, res) {
  //  Get header values of JSON payload from github required
  const data=getWebhookData(req,  param.HEADER_EVENT, param.HEADER_CONTENT_TYPE);

  //  Verify header values
  if (validate.validateWebhookRequest(param, data, res)) {
    param.APP_DEBUG=='true' ? console.log(`DEBUG:SUCCESS:VAL_JSON_KEYS: Json Keys Structure are Ok. Parameters: ${param.HEADER_EVENT} - ${param.HEADER_CONTENT_TYPE}`):null;

    //  Verify body values and repository exclusion
    if (validate.validateRequestBody(param, data)) {

      let jsonDataStr = JSON.stringify(data.jsonData, null, 2);
      let nameFileGH='';
      //  Write JSON received from Github if param.W_RCV_GH_ENABLED is true
      Boolean(param.MOD_W_RCV_GH_ENABLED)=='true'
        ? (
          nameFileGH = `temp/my_sbom_files/${param.GH_PREFIX_FILE}${data.nameRepository}${param.STR_SEPARATOR}${data.number}${param.JSON_EXTENSION}`,
          writePayloadToJsonFile(nameFileGH, jsonDataStr)
        )
        : null;

      //  File name e.g. ../temp/my_sbom_files/sbom-<reponame>.json
      data.sbomLocalFileName = `temp/my_sbom_files/${param.BOM_PREFIX_FILE}${data.nameRepository}${param.STR_SEPARATOR}${data.number}${param.JSON_EXTENSION}`;

      res.status(201).send(`Received and Processing`);

      //  Generate SBOM file with Trivy from setting : data.sbomFileName, data.urlRepository, data.base
      createSBOM(data)
      .then((stdout) => {
        console.log(stdout);
        const fileContent = readSBOMFile(data.sbomLocalFileName);
          //  Upload SBOM file to AWS S3 from local store
          data.sbomFileName = `${param.BOM_PREFIX_FILE}${data.nameRepository}${param.JSON_EXTENSION}`,
          
          dependencyTrackIngest(param, data, fileContent)
          .then(response => {
            console.log(response);  // JSON object
            removeSBOM(data);
          })
          .catch((err) => {
            console.log (err);
            process.exit(1);
          })
      })
      .catch(err => {
        const result= { status: 400, message: `DEBUG:ERR:SBOM: Creating SBOM file - Process failed ${err}`};
        console.log(JSON.stringify(result));
        res.end();
        process.exit(1);
      });
    } else {
      return res.status(200).send({ info: `DEBUG:ERR:VAL_JSON_VALUES: JSON values are invalid or skipped repository ${data.nameRepository}` })
    }   
  } else {
    param.APP_DEBUG=='true' ? console.log(`DEBUG:ERR:VAL_JSON_KEYS:  JSON key structure are invalid. ${data.nameRepository} repo 
      -Event:${data.event} -ContentType:${data.contentType} -Action:${data.action} -State:${data.state} 
      -Base:${data.base} -Merged:${data.merged} -Number:${data.number} -URL:${data.urlRepository}`) : null;

    return res.status(200).send({ error: `DEBUG:ERR:VAL_JSON_KEYS: JSON key structure are invalid ${data.nameRepository} repo 
    -Event:${data.event} -ContentType:${data.contentType} -Action:${data.action} -State:${data.state} 
    -Base:${data.base} -Merged:${data.merged} -Number:${data.number} 
    -URL:${data.urlRepository}`})
  }
});

const newLocal = 'uncaughtException';
  // You can also use the process.on('uncaughtException') event 
    // to handle uncaught exceptions in your Node.js process.
process.on(newLocal, (error) => {
  const jsonError = JSON.stringify(error);
  console.error(`CRITICAL:ERR: Caught exception: ${jsonError}`);
  process.exit(1);  

});

app.listen(param.APP_PORT, () => {
  param.APP_DEBUG=='true' ? console.log("Server running on port:", param.APP_PORT) : null;
});
