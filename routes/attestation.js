const express   = require('express');
const utils     = require('../utils');
const config    = require('../config.json');
const base64url = require('base64url');
const router    = express.Router();
const database  = require('./db');

router.post('/options', (request, response) => {
    if(!request.body || !request.body.username || !request.body.displayName) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Request missing display name or username field!'
        })
        return
    }

    let username = request.body.username;
    let displayName     = request.body.displayName;

    if(database[username] && database[username].registered) {
        response.json({
            'status': 'failed',
            'errorMessage': `Username ${username} already exists`
        })
        return
    }

    database[username] = {
        'name': displayName,
        'registered': false,
        'id': utils.randomBase64URLBuffer(),
        'authenticators': []
    }

    let challengeMakeCred    = utils.generateServerMakeCredRequest(username, displayName, database[username].id, request.body.attestation);
    challengeMakeCred.status = 'ok'
    challengeMakeCred.errorMessage = '';
    challengeMakeCred.extensions = request.body.extensions;
    challengeMakeCred.authenticatorSelection = request.body.authenticatorSelection;

    request.session.challenge = challengeMakeCred.challenge;
    request.session.username  = username;

    response.json(challengeMakeCred)
})

router.post('/result', (request, response) => {
    if(!request.body       || !request.body.id
    || !request.body.rawId || !request.body.response
    || !request.body.type  || request.body.type !== 'public-key' ) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!'
        })
        return
    }

    if (!utils.base64UrlChecker(request.body.id)) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Invalid id!'
        })
        return
    }

    let webauthnResp = request.body
    let clientData   = JSON.parse(base64url.decode(webauthnResp.response.clientDataJSON));

    /* Check challenge... */
    if(clientData.challenge !== request.session.challenge) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Challenges don\'t match!'
        })
    }

    /* ...and origin */
    if(clientData.origin !== config.origin) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Origins don\'t match!'
        })
    }

    /* ...and type */
    if(clientData.type !== 'webauthn.create') {
        response.json({
            'status': 'failed',
            'errorMessage': 'Type don\'t match!'
        }) 
    }

    /* ...and tokenBinding */
    if(clientData.tokenBinding) {
        response.json({
            'status': 'failed',
            'errorMessage': 'Token Binding don\`t support!'
        }) 
    }

    let result;
    if(webauthnResp.response.attestationObject) {
        result = utils.verifyAuthenticatorAttestationResponse(webauthnResp);

        if(result.verified) {
            database[request.session.username].authenticators.push(result.authrInfo);
            database[request.session.username].registered = true
        }
    } else {
        response.json({
            'status': 'failed',
            'errorMessage': 'Can not determine type of response!'
        })
    }

    if(result.verified) {
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
