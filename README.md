![dsabot](https://user-images.githubusercontent.com/115161133/233079779-f2ffa7ca-248e-45b1-87b6-8876aed0a7a1.jpg)

# DSAbot infosec tool
DSAbot is the acronymous of Dependency Security Analyzer bot. 
Its purpose is to integrate GitHub with OWASP Dependency Track.
Also, DSAbot generates a third-party components inventory in [CyloneDX](https://cyclonedx.org/) standard format and ingest it for security vulnerability scanning.
It is written in Node.js

## What does DSAbot do? 

1. Receive GitHub Merged PR event with JSON changed information file.
2. Analyze, Parse and Validate data.
3. Execute trivy binary to generate SBOM file from repository.
4. Ingest the SBOM json file in Dependency Track.  

All the transactions should be logged and validated.
All of the integration process should be encrypted.

This is a Node.js web application that interacts with the GitHub API to generate and upload SBOM (Software Bill of Materials) files. It also uses a dependency tracking tool called Dependency-Track to ingest the SBOM files and generate reports on the project's dependencies.

The application listens to incoming webhook events from GitHub and uses the data to generate SBOM files for the relevant repository. It can also retrieve a list of all the repositories in an organization and generate SBOM files for each repository.

If configured, the Dependency-Track tool is used to ingest the files and generate dependency reports. The application has some built-in error handling and logging, and it relies on environment variables for configuration.

## Table of Contents
1. [Requirements](#requirements)
2. [How to install](#how-to-install)
3. [Getting Started](#getting-started)
4. [User Manual](#user-manual)
5. [Reporting Issues](#reporting-issues)
6. [Contributing](#contributing)


## Requirements
1. NodeJS >= 14
2. [Github Token](https://docs.github.com/en/enterprise-server@3.6/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens) 
    + Readonly to repositories
2. [Github Webhook](https://docs.github.com/en/rest/orgs/webhooks?apiVersion=2022-11-28)
    + Payload URL = <dsabot-public-api-endpoint> e.g. https://public-dsabot-main.com/webhook
    + Content type = application/json
    + SSL verification = enable SSL
    + Individual events = Pull requests
3. [Trivy v0.42.0](https://github.com/aquasecurity/trivy/) (included in package.json)
4. [Dependency Track](https://docs.dependencytrack.org/)
5. Rename the .env.template file to .env and fill in the required information

## Cloning the repository
```
git clone https://github.com/valentinalmiron/dsabot.git
```
## Documentation for API Endpoints

All URIs are relative to https://dsabot-url/

HTTP request | Description
------------ | -------------
**GET** /:org:/repos | get All repositories
**GET** /:org:/:repo/:branch/sbom | Build specific SBOM file from org;repo;branch to ingest into Dependency Track
**GET** / | get help
**GET** /status | get Status
**POST** /webhook | Receive GitHub Webhook to ingest SBOM into Dependency Track


## Diagram 
 ```mermaid
graph TD;
    GitHub-WebHook-->DSAbot-API;
    DSAbot-API-->GitHub-Repository;
    GitHub-Repository-->DSAbot-API;
    DSAbot-API-->Dependency-Track;
```
