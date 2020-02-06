const express = require('express');
const app = express();
const path = require('path');
const fs = require('fs');
const bodyParser = require('body-parser');

const Honeypot = require('./Honeypot');
let honeypots = JSON.parse(fs.readFileSync('./honeypots.json')).map(entry => {
    return new Honeypot(
        {
            id: entry.id, 
            name: entry.name, 
            url: entry.url, 
            trustCert: entry.trustCert
        }
        , { 
            authEnabled: entry.authEnabled, 
            username: entry.username, 
            password: entry.password
        }
    )
})

function getHoneypotById(id) {
    return honeypots.find(hp => hp.id == id);
}

const nav = [
    {
        name: 'Home',
        href: '/'
    },
    {
        name: 'Honeypots',
        href: '/honeypots'
    }
];

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'pug');

app.use(bodyParser.urlencoded({ extended: true }));
app.get('/', (req, res) => {
    res.render('index', { honeypots, nav });
});

app.get('/honeypots', (req, res) => {
    res.render('honeypots', { honeypots, nav });
});

app.get('/honeypot/:id', async (req, res) => {
    const id = req.params.id;
    const honeypot = getHoneypotById(id);

    if (!honeypot) {
        res.render('honeypot', { nav, id, notFound: true});
        return;
    }

    let services;
    let err;

    try {
        services = await honeypot.getServices();
    } catch (e) {
        err = e;
    }

    res.render('honeypot', { nav, id, services, hp: honeypot, err });

});

app.get('/honeypot/:id/edit', async (req, res) => {
    const id = req.params.id;
    const honeypot = getHoneypotById(id);

    if (!honeypot) {
        res.render('editHoneypot', { nav, id, notFound: true});
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

    res.render('editHoneypot', { nav, id, hp: honeypot, remoteConfig, remoteError });
});

app.get('/honeypot/:id/stop/:service', (req, res) => {
    const {id, service} = req.params;
    const honeypot = getHoneypotById(id);

    if (!honeypot) {
        res.render('honeypot', { nav, id, notFound: true});
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
        res.render('honeypot', { nav, id, notFound: true});
        return;
    }

    honeypot.start(service).then(code => {
        res.redirect('/honeypot/' + id);
    }).catch(err => {
    });

});



app.post('/honeypot/:id/edit', async (req, res) => {
    const id = req.params.id;
    const honeypot = getHoneypotById(id);
    const { service } = req.body;

    if (!honeypot) {
        res.render('editHoneypot', { nav, id, notFound: true});
        return;
    }

    try {

        if (!service) {

            const { name, url, trustCert, useAuth, username, password } = req.body;
        
            honeypot.name = name;
            honeypot.url = url;
            honeypot.trustCert = trustCert === 'true';
            honeypot.authEnabled = useAuth === 'true';
            honeypot.username = username;
            honeypot.password = password;
        
            fs.writeFile('honeypots.json', JSON.stringify(honeypots, null, 2), () => {});

        }
        
    } catch (e) { /* Remote edit */}

    try {

        const {
            service,
            bind,
            port
        } = req.body;

        const res = await honeypot.setConfig(service, bind, port);
    } catch (e) {}

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

    res.render('editHoneypot', { nav, id, hp: honeypot, remoteError, remoteConfig, successMessage: 'You successfully edited the honeypot!' });
});

app.get('/honeypots/add', (req, res) => {
    res.render('addHoneypot', { nav })
});

app.post('/honeypots/add', (req, res) => {
    const { name, url, trustCert, useAuth, username, password } = req.body;
        
    let nextId;
    for (nextId = 1; true; nextId++) {
        if (!getHoneypotById(nextId)) {
            break;
        }
    }

    let hp = new Honeypot({ id: nextId, name, url, trustCert: trustCert === 'true' }, { authEnabled: useAuth === 'true', username, password });

    honeypots.push(hp);
    saveConfig();
    res.redirect('/honeypots');
});

app.get('/honeypot/:id/delete', (req, res) => {
    const { id } = req.params;
    const honeypot = getHoneypotById(id);

    if (!honeypot) {
        res.sendStatus(404);
        return;
    }
    res.render('deleteHoneypot', { nav, hp: honeypot})
});

app.post('/honeypot/:id/delete', (req, res) => {
    const { id } = req.params;
    honeypots = honeypots.filter(hp => hp.id != id);
    saveConfig();
    res.redirect('/honeypots');
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