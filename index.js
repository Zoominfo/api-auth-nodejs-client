/**
 * Zoominfo API Authentication Client
 *
 * Get JWT access token using one of the following ways
 * - PKI Auth flow using username, client id and private key
 * - Username and Password
 */

const axios     = require('axios');
const rs        = require('jsrsasign');
const AUTH_URL  = 'https://api.zoominfo.com/authenticate';

module.exports = {
    getAccessTokenViaPKI:       getAccessTokenViaPKI,
    getAccessTokenViaBasicAuth: getAccessTokenViaBasicAuth
}

function getAccessTokenViaBasicAuth(username, password) {
    return axios.post(AUTH_URL,
        {
            username: username,
            password: password
        })
        .then(res => {
            return res.data.jwt;
        })
        .catch(err => {
            return err
        });
}

function getAccessTokenViaPKI(username, clientId, privateKey) {
    const dtNow = Date.now();
    let alg = "RS256";
    let iss = "zoominfo-api-auth-client-nodejs";
    let aud = "enterprise_api";
    let header = {
        "typ": "JWT",
        "alg": alg
    };
    let data = {
        "aud": aud,
        "iss": iss,
        "username": username,
        "client_id": clientId,
        "iat": getIAT(dtNow),
        "exp": getEXP(dtNow)
    };
    let sHeader  = JSON.stringify(header);
    let sPayload = JSON.stringify(data);

    let clientJWT = rs.jws.JWS.sign(header.alg, sHeader, sPayload, privateKey);
    return axios.post(AUTH_URL,
        {},
        {
            headers: {
                'Authorization': 'Bearer ' + clientJWT
            }
        }).then(res => {
            return res.data.jwt;
        }).catch(err => {
            return err
    });
}

function getIAT(dtNow) {
    let iat = Math.floor(dtNow / 1000);
    iat = iat - 60;
    return iat;
}
function getEXP(dtNow) {
    let exp = Math.floor(dtNow / 1000) + (5 * 60);
    exp = exp - 60;
    return exp;
}

