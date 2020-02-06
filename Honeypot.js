const fetch = require('node-fetch');
const https = require('https');

class Honeypot {

    constructor({id, name, url, trustCert}, {authEnabled, username, password}) {
        this.id = id;
        this.name = name;
        this.url = url;
        this.trustCert = trustCert;
        this.authEnabled = authEnabled;
        this.username = username;
        this.password = password;
    }

    getServices() {
        return new Promise((resolve, reject) => {
            let agent = new https.Agent({
                rejectUnauthorized: !this.trustCert
            })
            let config = {
                agent,
                headers: {}
            };
            if (this.authEnabled) {
                config.headers.authorization = 'Basic ' + new Buffer(this.username + ':' + this.password).toString('base64');
            }
            fetch(this.url + '/honeypot/services', config)
            .then(res => {
                if (res.status !== 200) {
                    reject(res.status);
                }
                return res.json();
            })
            .then(json => resolve(json))
            .catch(err => {
                reject(err.code);
            });
        });
    }

    stop(service) {
        return new Promise((resolve, reject) => {
            let agent = new https.Agent({
                rejectUnauthorized: !this.trustCert
            })
            let config = {
                agent,
                headers: {
                    'Content-Type': 'application/json'
                },
                method: 'POST',
                body: JSON.stringify({service})
            };
            if (this.authEnabled) {
                config.headers.authorization = 'Basic ' + new Buffer(this.username + ':' + this.password).toString('base64');
            }
            fetch(this.url + '/honeypot/stop', config)
            .then(res => resolve(res.status))
            .catch(err => reject(err));
        });
    }

    start(service) {
        return new Promise((resolve, reject) => {
            let agent = new https.Agent({
                rejectUnauthorized: !this.trustCert
            })
            let config = {
                agent,
                headers: {
                    'Content-Type': 'application/json'
                },
                method: 'POST',
                body: JSON.stringify({service})
            };
            if (this.authEnabled) {
                config.headers.authorization = 'Basic ' + new Buffer(this.username + ':' + this.password).toString('base64');
            }
            fetch(this.url + '/honeypot/start', config)
            .then(res => resolve(res.status))
            .catch(err => reject(err));
        });
    }

    getRemoteConfig() {
        return new Promise((resolve, reject) => {
            let agent = new https.Agent({
                rejectUnauthorized: !this.trustCert
            })
            let config = {
                agent,
                headers: {
                    'Content-Type': 'application/json'
                },
                method: 'GET'
            };
            if (this.authEnabled) {
                config.headers.authorization = 'Basic ' + new Buffer(this.username + ':' + this.password).toString('base64');
            }
            fetch(this.url + '/honeypot/config', config)
            .then(res => res.json())
            .then(res => resolve(res))
            .catch(err => reject(err));
        });
    }

    setConfig(service, bind, port) {
        return new Promise((resolve, reject) => {
            let agent = new https.Agent({
                rejectUnauthorized: !this.trustCert
            })
            let config = {
                agent,
                headers: {
                    'Content-Type': 'application/json'
                },
                method: 'POST',
                body: JSON.stringify({
                    service,
                    bind,
                    port
                })
            };
            if (this.authEnabled) {
                config.headers.authorization = 'Basic ' + new Buffer(this.username + ':' + this.password).toString('base64');
            }
            fetch(this.url + '/honeypot/config', config)
            .then(res => resolve(res.status))
            .catch(err => reject(err));
        });
    }

}
module.exports = Honeypot;