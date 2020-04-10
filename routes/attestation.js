const express = require('express');
const utils = require('../libs/utils');
const attestation = require('../libs/attestation');
const config = require('../config.json');
const base64url = require('base64url');
const router = express.Router();
const database = require('./db');

const fidoMdsRootCert =
    "-----BEGIN CERTIFICATE-----\n" +
    "MIICQzCCAcigAwIBAgIORqmxkzowRM99NQZJurcwCgYIKoZIzj0EAwMwUzELMAkG\n" +
    "A1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxsaWFuY2UxHTAbBgNVBAsTFE1ldGFk\n" +
    "YXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRSb290MB4XDTE1MDYxNzAwMDAwMFoX\n" +
    "DTQ1MDYxNzAwMDAwMFowUzELMAkGA1UEBhMCVVMxFjAUBgNVBAoTDUZJRE8gQWxs\n" +
    "aWFuY2UxHTAbBgNVBAsTFE1ldGFkYXRhIFRPQyBTaWduaW5nMQ0wCwYDVQQDEwRS\n" +
    "b290MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEFEoo+6jdxg6oUuOloqPjK/nVGyY+\n" +
    "AXCFz1i5JR4OPeFJs+my143ai0p34EX4R1Xxm9xGi9n8F+RxLjLNPHtlkB3X4ims\n" +
    "rfIx7QcEImx1cMTgu5zUiwxLX1ookVhIRSoso2MwYTAOBgNVHQ8BAf8EBAMCAQYw\n" +
    "DwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU0qUfC6f2YshA1Ni9udeO0VS7vEYw\n" +
    "HwYDVR0jBBgwFoAU0qUfC6f2YshA1Ni9udeO0VS7vEYwCgYIKoZIzj0EAwMDaQAw\n" +
    "ZgIxAKulGbSFkDSZusGjbNkAhAkqTkLWo3GrN5nRBNNk2Q4BlG+AvM5q9wa5WciW\n" +
    "DcMdeQIxAMOEzOFsxX9Bo0h4LOFE5y5H8bdPFYW+l5gy1tQiJv+5NUyM2IBB55XU\n" +
    "YjdBz56jSA==\n" +
    "-----END CERTIFICATE-----\n";

router.post('/options', (request, response) => {
    if (!request.body || !request.body.username || !request.body.displayName) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Request missing display name or username field!'
        })
        return
    }

    const username = request.body.username;
    const displayName = request.body.displayName;
    let excludeCredentials;

    if (database[username] && database[username].registered) {
        excludeCredentials = [{
            'type': 'public-key',
            'id': database[username].authenticators[0].credID
        }]
    } else {
        database[username] = {
            'name': displayName,
            'registered': false,
            'id': utils.randomBase64URLBuffer(),
            'authenticators': []
        }
    }


    let challengeMakeCred = attestation.generateServerMakeCredRequest(username, displayName, database[username].id, request.body.attestation);
    challengeMakeCred.status = 'ok'
    challengeMakeCred.errorMessage = '';
    challengeMakeCred.extensions = request.body.extensions;
    challengeMakeCred.authenticatorSelection = request.body.authenticatorSelection;
    challengeMakeCred.excludeCredentials = excludeCredentials;


    request.session.challenge = challengeMakeCred.challenge;
    request.session.username = username;

    response.json(challengeMakeCred)
})

router.post('/result', (request, response) => {
    if (!request.body || !request.body.id
        || !request.body.rawId || !request.body.response
        || !request.body.type || request.body.type !== 'public-key') {
        response.json({
            'status': 'failed',
            'errorMessage': 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!'
        })
        return
    }

    if (!utils.isBase64UrlEncoded(request.body.id)) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Invalid id!'
        })
        return
    }

    const webauthnResp = request.body
    const clientData = JSON.parse(base64url.decode(webauthnResp.response.clientDataJSON));

    /* Check challenge... */
    if (clientData.challenge !== request.session.challenge) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Challenges don\'t match!'
        })
    }

    /* ...and origin */
    if (clientData.origin !== config.origin) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Origins don\'t match!'
        })
    }

    /* ...and type */
    if (clientData.type !== 'webauthn.create') {
        response.json({
            'status': 'failed',
            'errorMessage': 'Type don\'t match!'
        })
    }

    /* ...and tokenBinding */
    if (clientData.tokenBinding) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Token Binding don\`t support!'
        })
    }

    let result;
    if (webauthnResp.response.attestationObject) {
        result = attestation.verifyAuthenticatorAttestationResponse(webauthnResp);

        if (result.verified) {
            database[request.session.username].authenticators.push(result.authrInfo);
            database[request.session.username].registered = true
        }
    } else {
        response.json({
            'status': 'failed',
            'errorMessage': 'Can not determine type of response!'
        })
    }

    if (result.verified) {
        request.session.loggedIn = true;
        response.json({
            'status': 'ok',
            'errorMessage': ''
        })
    } else {
        response.json({
            'status': 'failed',
            'errorMessage': 'Can not authenticate signature!'
        })
    }
})

module.exports = router;
