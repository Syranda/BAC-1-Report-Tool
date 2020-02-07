const fetch = require('node-fetch');
const https = require('https');
const http = require('http');

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
            fetch(this.url + '/honeypot/services', this.getFetchConfig('GET'))
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
            fetch(this.url + '/honeypot/stop', this.getFetchConfig('POST', { service }))
            .then(res => resolve(res.status))
            .catch(err => reject(err));
        });
    }

    start(service) {
        return new Promise((resolve, reject) => {
            fetch(this.url + '/honeypot/start', this.getFetchConfig('POST', { service }))
            .then(res => resolve(res.status))
            .catch(err => reject(err));
        });
    }

    getRemoteConfig() {
        return new Promise((resolve, reject) => {
            fetch(this.url + '/honeypot/config', this.getFetchConfig('GET'))
            .then(res => res.json())
            .then(res => resolve(res))
            .catch(err => reject(err));
        });
    }

    setConfig(service, bind, port) {
        return new Promise((resolve, reject) => {
            fetch(this.url + '/honeypot/config', this.getFetchConfig('POST', { service, bind, port}))
            .then(res => resolve(res.status))
            .catch(err => reject(err));
        });
    }

    getReport() {
        return new Promise((resolve, reject) => {
            fetch(this.url + '/honeypot/report', this.getFetchConfig('GET'))
            .then(res => res.json())
            .then(json => resolve(json))
            .catch(err => reject(err));
        });
    }

    getFetchConfig(method, body) {
        const url = new URL(this.url);
        let agent;
        if (url.protocol === 'https') {
            agent = new https.Agent({
                rejectUnauthorized: !this.trustCert
            })
        } else {
            agent = new http.Agent();
        }
        let config = {
            agent,
            headers: {
                'Content-Type': 'application/json'
            },
            method,
            body: body ? JSON.stringify(body) : undefined
        };

        if (this.authEnabled) {
            config.headers.authorization = 'Basic ' + new Buffer(this.username + ':' + this.password).toString('base64');
        }

        return config;
    }

}
module.exports = Honeypot;