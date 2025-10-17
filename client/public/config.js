const config = {
    development: {
        wsUrl: 'ws://localhost:10000',
        apiUrl: 'http://localhost:10000'
    },
    production: {
        wsUrl: 'wss://balachatmessage.onrender.com',
        apiUrl: 'https://balachatmessage.onrender.com'
    }
};

const environment = window.location.hostname === 'localhost' ? 'development' : 'production';

window.APP_CONFIG = config[environment];