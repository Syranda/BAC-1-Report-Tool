const topCtx = document.getElementById('top-service').getContext('2d');
const originCtx = document.getElementById('top-origin').getContext('2d');
const unCtx = document.getElementById('top-username').getContext('2d');
const pwCtx = document.getElementById('top-password').getContext('2d');


function loadReports(report) {
    const data = report;
    let topServicesValues = Object.keys(data).map(key => {
        return {
            service: key,
            value: data[key].filter(rep => rep.type === 'Authentication').length
        }
    });

    const topServicesChart = new Chart(topCtx, {
        // The type of chart we want to create
        type: 'doughnut',
    
        // The data for our dataset
        data: {
            datasets: [{
                data: topServicesValues.map(v => v.value),
                backgroundColor: ['#e74c3c', '#3498db', '#9b59b6', '#f1c40f', '#1abc9c']
            }],
        
            // These labels appear in the legend and in the tooltips when hovering different arcs
            labels: topServicesValues.map(v => v.service)
        },
    
        // Configuration options go here
        options: {}
    });

    let originValues = Object.keys(data).map(key => {
        return data[key].filter(rep => rep.type === 'Authentication').map(rep => rep.data.from.origin).filter(value => value);
    }).flat(1);
    originValues = [... new Set(originValues)].map(origin => {

        return {
            origin,
            attacks: Object.keys(data).map(key => {
                return data[key].filter(rep => rep.type === 'Authentication' && rep.data.from.origin === origin);
            }).flat(1).length
        };

    }).sort((a, b) => {
        return b.attacks - a.attacks;
    });

    let originData, originLabels;
    if (originValues.length > 7) {
        originData = [originValues.slice(0, 7).map(ov => ov.attacks), originValues.slice(7).reduce((acc, current) => acc + current.attacks, 0)].flat(1);
        originLabels = [originValues.slice(0, 7).map(ov => ov.origin), 'Others'].flat(1);
    } else {
        originData = originValues.map(ov => ov.attacks);
        originLabels = originValues.map(ov => ov.origin);
    }


    const topOriginChart = new Chart(originCtx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: originData,
                backgroundColor: ['#e74c3c', '#3498db', '#9b59b6', '#f1c40f', '#1abc9c', '#34495e', '#ecf0f1']
            }],
            labels: originLabels
        }
    });

    let usernameData = Object.keys(data).map(key => {
        return data[key].filter(rep => rep.type === 'Authentication' && rep.data.password).map(rep => rep.data.password.username).filter(value => value);
    }).flat(1);
    usernameData = [...new Set(usernameData)].map(un => {
        return {
            username: un,
            used: Object.keys(data).map(key => {
                return data[key].filter(rep => rep.type === 'Authentication' && rep.data.password && rep.data.password.username === un);
            }).flat(1).length
        }
    }).sort((a, b) => b.used - a.used);

    let unData, unLabels;
    if (usernameData.length > 7) {
        unData = [usernameData.slice(0, 7).map(ov => ov.used), usernameData.slice(7).reduce((acc, current) => acc + current.used, 0)].flat(1);
        unLabels = [usernameData.slice(0, 7).map(ov => ov.username), 'Others'].flat(1);
    } else {
        unData = usernameData.map(ov => ov.used);
        unLabels = usernameData.map(ov => ov.username);
    }

    const topUsernameChart = new Chart(unCtx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: unData,
                backgroundColor: ['#e74c3c', '#3498db', '#9b59b6', '#f1c40f', '#1abc9c', '#34495e', '#ecf0f1']
            }],
            labels: unLabels
        }
    });

    let passwordData = Object.keys(data).map(key => {
        return data[key].filter(rep => rep.type === 'Authentication' && rep.data.password).map(rep => rep.data.password.password).filter(value => value);
    }).flat(1);
    passwordData = [...new Set(passwordData)].map(pw => {
        return {
            password: pw,
            used: Object.keys(data).map(key => {
                return data[key].filter(rep => rep.type === 'Authentication' && rep.data.password && rep.data.password.password === pw);
            }).flat(1).length
        }
    }).sort((a, b) => b.used - a.used);

    let pwData, pwLabels;
    if (passwordData.length > 7) {
        pwData = [passwordData.slice(0, 7).map(ov => ov.used), passwordData.slice(7).reduce((acc, current) => acc + current.used, 0)].flat(1);
        pwLabels = [passwordData.slice(0, 7).map(ov => ov.password), 'Others'].flat(1);
    } else {
        pwData = passwordData.map(ov => ov.used);
        pwLabels = passwordData.map(ov => ov.password);
    }

    const topPasswordChart = new Chart(pwCtx, {
        type: 'doughnut',
        data: {
            datasets: [{
                data: pwData,
                backgroundColor: ['#e74c3c', '#3498db', '#9b59b6', '#f1c40f', '#1abc9c', '#34495e', '#ecf0f1']
            }],
            labels: pwLabels
        }
    });

}
