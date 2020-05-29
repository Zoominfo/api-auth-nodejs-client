# Zoominfo API Auth Client

An API Authentication client to generate access token for Zoominfo API

### Installation
```
npm i zoominfo-api-auth-client
```

### Usage

#### Get access token using client id and private key
```
var authClient = require('zoominfo-api-auth-client');
var pkiAuthPromise = authClient.getAccessTokenViaPKI("username", "clientId", "privateKey");
pkiAuthPromise.then(token => console.log(token));
```
#### Get access token using username and password
```
var authClient = require('zoominfo-api-auth-client');
var basicAuthPromise = authClient.getAccessTokenViaBasicAuth("username", "password");
basicAuthPromise.then(token => console.log(token));
```