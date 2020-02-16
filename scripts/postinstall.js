const readLine = require('readline');
const fs = require('fs');
const validator = require('validator');

const rl = readLine.createInterface({
    input: process.stdin,
    output: process.stdout
});

let omit = false;

rl._writeToOutput = message => {
    rl.output.write(omit && message.length === 1 ? '*' : message);
}

function askYesNo(message, defaultAnswer) {
    return new Promise((resolve, reject) => {
        let display = defaultAnswer ? ' [Y/n]' : ' [y/N]';
        rl.question(`${message}${display}: `, answer => {
            resolve(answer.length > 0 ? answer.toLowerCase() === 'y' : defaultAnswer);
        });
    });
}

function askPath(message, defaultPath) {
    return new Promise((resolve, reject) => {
        rl.question(`${message}${defaultPath ? ` [${defaultPath}]` : `` }: `, answer => {
            resolve(answer.length > 0 ? answer : defaultPath);
        });
    });
}

function askNumber(message, defaultNumber) {
    return new Promise((resolve, reject) => {
        rl.question(`${message} [${defaultNumber}]: `, answer => {
            resolve(answer.length > 0 ? answer : defaultNumber);
        });
    });
}

function askString(message, defaultString) {
    return new Promise((resolve, reject) => {
        rl.question(message + (defaultString ? ` [${defaultString}]: ` : ': '), answer => {
            resolve(answer.length > 0 ? answer : defaultString);
        });
    });
}


(async function setup() {

    let config = JSON.parse(fs.readFileSync('./config.json'));
    
    let correct = false;

    do {

        let bind;
        let isIP = false;
        do {
            bind = await askString('On which address should the reporting tool listen on?', '0.0.0.0');
            isIP = validator.isIP(bind);
            if (!isIP) {
                console.log('Please enter a valid IP address');
            }
        } while (!isIP);
        config.bind = bind;

        let port;
        let isPort = false;
        do {
            port = await askNumber('On which port should the reporting tool listen on?', 8080);
            isPort = validator.isPort(port + '');
            if (!isPort) {
                console.log('Plea enter a valid port');
            }
        } while (!isPort);
        config.port = port;

        const useSSL = await askYesNo('Do you want to use SSL?', true);
        config.ssl.enabled = useSSL;

        if (useSSL) {
            let keyFile;

            do {
                keyFile = await askPath('Where is the private key located?', './ssl/key.pem');
                if (!fs.existsSync(keyFile)) {
                    console.log('The specified private key does not exist');
                }
            } while(!fs.existsSync(keyFile));
            config.ssl.key = keyFile;

            let passphrase = await askPath('Enter the passphrase of the key [Empty for none]');
            config.ssl.passphrase = passphrase;
            
            let certFile;

            do {
                certFile = await askPath('Where is the certificate file located? ', './ssl/cert.pem')
                if (!fs.existsSync(certFile)) {
                    console.log('The specified private key does not exist');
                }
            } while(!fs.existsSync(certFile));
            config.ssl.cert = certFile;

        } else {
            config.ssl.key = "";
            config.ssl.cert = "";
            config.ssl.passphrase = "";
        }

        console.log(JSON.stringify(config, null, 2));
        correct = await askYesNo('Is this config correct?', true);

    } while (!correct);

    fs.writeFileSync('./config.json', JSON.stringify(config, null, 2));

    rl.close();



})();

