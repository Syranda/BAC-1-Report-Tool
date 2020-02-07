const express = require('express');
const app = express();
const path = require('path');
const fs = require('fs');
const bodyParser = require('body-parser');
const csrf = require('csurf')({ cookie: true});
const cookieParser = require('cookie-parser');
const { check, validationResult } = require('express-validator');

const Honeypot = require('./Honeypot');
let honeypots = JSON.parse(fs.readFileSync('./honeypots.json')).map(entry => {
    return new Honeypot(
        {
            id: entry.id, 
            name: entry.name, 
            url: entry.url, 
            trustCert: entry.trustCert
        }, 
        { 
            authEnabled: entry.authEnabled, 
            username: entry.username, 
            password: entry.password
        }
    )
})

function getHoneypotById(id) {
    return honeypots.find(hp => hp.id == id);
}

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());

app.get('/', (req, res) => {
    res.render('honeypots', { honeypots });
});

app.get('/honeypot/:id', async (req, res) => {
    const id = req.params.id;
    const honeypot = getHoneypotById(id);

    if (!honeypot) {
        res.render('honeypot', { id, notFound: true});
        return;
    }

    let services;
    let err;

    try {
        services = await honeypot.getServices();
    } catch (e) {
        err = e;
    }

    res.render('honeypot', { id, services, hp: honeypot, err });

});

app.get('/honeypot/:id/stop/:service', (req, res) => {
    const {id, service} = req.params;
    const honeypot = getHoneypotById(id);

    if (!honeypot) {
        res.render('honeypot', { id, notFound: true});
        return;
    }

    honeypot.stop(service).then(code => {
        res.redirect('/honeypot/' + id);
    }).catch(err => {
        console.log(err);
    });

});

app.get('/honeypot/:id/start/:service', (req, res) => {
    const {id, service} = req.params;
    const honeypot = getHoneypotById(id);

    if (!honeypot) {
        res.render('honeypot', { id, notFound: true});
        return;
    }

    honeypot.start(service).then(code => {
        res.redirect('/honeypot/' + id);
    }).catch(err => {
    });

});

app.get('/honeypot/:id/edit', csrf, async (req, res) => {
    const id = req.params.id;
    const honeypot = getHoneypotById(id);

    if (!honeypot) {
        res.render('editHoneypot', { id, notFound: true});
        return;
    }

    let remoteConfig;
    let remoteError;

    try {
        remoteConfig = await honeypot.getRemoteConfig();
        remoteConfig = Object.keys(remoteConfig).map(key => {
            let newKey = key.substring(0, key.length - 'Config'.length);
            switch (newKey) {
                case 'telnet':
                    newKey = newKey.charAt(0).toUpperCase() + newKey.slice(1);
                    break;
                default:
                    newKey = newKey.toUpperCase();
                    break;
            }
            return {
                service: newKey,
                bind: remoteConfig[key].bind,
                port: remoteConfig[key].port,
            }
        });
    } catch (e) {
        remoteError = e;
    }

    res.render('editHoneypot', { id, hp: honeypot, remoteConfig, remoteError, csrfToken: req.csrfToken() });
});

app.post('/honeypot/:id/editLocal', [
    csrf,
    check('name')
        .notEmpty().withMessage('Please enter a name'),
    check('url')
        .notEmpty().withMessage('Please enter an url')
        .bail()
        .isURL({ protocols: ['http', 'https'], require_tld: false }).withMessage('Please enter a valid url')
], async (req, res) => {

    const id = req.params.id;
    const honeypot = getHoneypotById(id);

    if (!honeypot) {
        res.render('editHoneypot', { id, notFound: true});
        return;
    }

    let remoteConfig;
    let remoteError;

    const { name, url, trustCert, useAuth, username, password } = req.body;

    honeypot.name = name;
    honeypot.url = url;
    honeypot.trustCert = trustCert === 'true';
    honeypot.authEnabled = useAuth === 'true';
    honeypot.username = username;
    honeypot.password = password;

    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        res.render('editHoneypot', { id, hp: honeypot, errors: errors.array(), csrfToken: req.csrfToken() });
        return;
    }


    fs.writeFile('honeypots.json', JSON.stringify(honeypots, null, 2), () => {});

    try {
        remoteConfig = await honeypot.getRemoteConfig();
        remoteConfig = Object.keys(remoteConfig).map(key => {
            let newKey = key.substring(0, key.length - 'Config'.length);
            switch (newKey) {
                case 'telnet':
                    newKey = newKey.charAt(0).toUpperCase() + newKey.slice(1);
                    break;
                default:
                    newKey = newKey.toUpperCase();
                    break;
            }
            return {
                service: newKey,
                bind: remoteConfig[key].bind,
                port: remoteConfig[key].port,
            }
        });
    } catch (e) {
        remoteError = e;
    }

    res.render('editHoneypot', { id, hp: honeypot, remoteError, remoteConfig, successMessage: 'You successfully edited the honeypot!', csrfToken: req.csrfToken() });
});

app.post('/honeypot/:id/editRemote', [
    csrf,
    check('service').notEmpty(),
    check('bind')
        .notEmpty().withMessage('Please enter an IP address to listen on')
        .bail()
        .isIP().withMessage('Please enter a valid IP address'),
    check('port')
        .notEmpty().withMessage('Please enter a port')
        .bail()
        .isPort().withMessage('Please enter a valid port')
], async (req, res) => {
    
    const id = req.params.id;
    const honeypot = getHoneypotById(id);

    if (!honeypot) {
        res.render('editHoneypot', { id, notFound: true});
        return;
    }

    let remoteConfig, remoteError;

    try {
        remoteConfig = await honeypot.getRemoteConfig();
        remoteConfig = Object.keys(remoteConfig).map(key => {
            let newKey = key.substring(0, key.length - 'Config'.length);
            switch (newKey) {
                case 'telnet':
                    newKey = newKey.charAt(0).toUpperCase() + newKey.slice(1);
                    break;
                default:
                    newKey = newKey.toUpperCase();
                    break;
            }
            return {
                service: newKey,
                bind: remoteConfig[key].bind,
                port: remoteConfig[key].port,
            }
        });
    } catch (e) {
        remoteError = e;
    }

    const errors = validationResult(req);

    if (!errors.isEmpty()) {
        res.render('editHoneypot', { id, hp: honeypot, remoteConfig, remoteError, errors: errors.array(), csrfToken: req.csrfToken() });
        return;
    }
    const {
        service,
        bind,
        port
    } = req.body;

    await honeypot.setConfig(service, bind, port);

    res.render('editHoneypot', { id, hp: honeypot, remoteError, remoteConfig, successMessage: 'You successfully edited the honeypot!', csrfToken: req.csrfToken() });

});

app.get('/honeypots/add', csrf, (req, res) => {
    res.render('addHoneypot', { csrfToken: req.csrfToken() })
});

app.post('/honeypots/add', [
    csrf,
    check('name')
        .notEmpty().withMessage('Please enter a name'),
    check('url')
        .notEmpty().withMessage('Please enter an url')
        .bail()
        .isURL({ protocols: ['http', 'https'], require_tld: false }).withMessage('Please enter a valid url (http / https)')
], (req, res) => {

    const errors = validationResult(req);
    const { name, url, trustCert, useAuth, username, password } = req.body;

    if (!errors.isEmpty()) {
        res.render('addHoneypot', { 
            csrfToken: req.csrfToken(), 
            errors: errors.array(),  
            name,
            url,
            trustCert,
            useAuth,
            username,
            password
        })
        return;
    }
        
    let nextId;
    for (nextId = 1; true; nextId++) {
        if (!getHoneypotById(nextId)) {
            break;
        }
    }

    let hp = new Honeypot({ id: nextId, name, url, trustCert: trustCert === 'true' }, { authEnabled: useAuth === 'true', username, password });

    honeypots.push(hp);
    saveConfig();
    res.redirect('/');
});

app.get('/honeypot/:id/delete', csrf, (req, res) => {
    const { id } = req.params;
    const honeypot = getHoneypotById(id);

    if (!honeypot) {
        res.sendStatus(404);
        return;
    }
    res.render('deleteHoneypot', { hp: honeypot, csrfToken: req.csrfToken()})
});

app.post('/honeypot/:id/delete', csrf, (req, res) => {
    const { id } = req.params;
    honeypots = honeypots.filter(hp => hp.id != id);
    saveConfig();
    res.redirect('/');
});

app.get('/honeypot/:id/report', async (req, res) => {
    const id = req.params.id;
    const honeypot = getHoneypotById(id);

    if (!honeypot) {
        res.render('editHoneypot', { id, notFound: true});
        return;
    }

    res.render('report', { id, hp: honeypot, report: await honeypot.getReport() });
});

app.get('/static/**', (req, res) => {
    const file = path.join(__dirname, req.path);
    if (!fs.existsSync(file)) {
        res.sendStatus(404);
        return;
    }
    res.sendFile(file);
});

function saveConfig() {
    fs.writeFileSync('honeypots.json', JSON.stringify(honeypots, null, 2));
}

app.listen(8080);