const axios = require('axios');

function getDataFromCache(url) {
    let cache = axios.get(`https://api.larger.io/v1/search/key/XCMQFKTB3O4JH3B03B5GEPY4URZYWG6E?domain=${url}&live=0`);
    return cache;
}

function getDataByCrawl(url) {
    let crawl = axios.get(`https://api.larger.io/v1/search/key/XCMQFKTB3O4JH3B03B5GEPY4URZYWG6E?domain=${url}&live=1`);
    return crawl;
}

async function processRequest(url) {
    let results;

    try {
        results = await getDataFromCache(url);
        
    } catch (err) {
        try {
            results = await getDataByCrawl(url);
            
        } catch {
            return "Can not load data from largeio";
        }

    } finally {
        dataResults = results.data;
        dataResults['technologies'] = dataResults['apps'];
        delete dataResults['apps'];
        return (dataResults);
    }
}

exports.largeio = async function (url) {
    let results = await processRequest(url);
    return new Promise((resolve, reject) => {
        resolve(JSON.stringify(results));
    })
}