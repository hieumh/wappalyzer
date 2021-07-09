const request = require('async-request')
const fs = require('fs')
const axios = require('axios');
const fetch = require('node-fetch');

let hostDatabase = "database"
let portDatabase ="27017"

let hostServerApi = "api-server"
let portServerApi = "5000"

function getHostFromUrl(url){
    if(url.split('//').length == 2){
        return url.split('//')[1].split('.')[0]
    }
    return url.split('.')[0]
}

async function takeScreenshot(url, token){
    let picName = '/images/' + token + '.png';
    let picPath = __dirname + picName;
    const response = await fetch(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/screenshot?url=${url}&token=${token}`)
    const buffer = await response.buffer();
    fs.writeFileSync(picPath, buffer);
    return picName
}

async function checkCms(url, token){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/cmseek?url=${url}&token=${token}`)
    return result.body
}

// get dns information
async function getDnsDig(url){
    url = decodeURIComponent(url)
    url = url.split("//")[1]
    if(url[url.length-1] == "/"){
        url = url.slice(0,-1)
    }
    url = encodeURIComponent(url)
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/dig?url=${url}`)
    return result.body
}

async function getDnsFierce(url, token){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/fierce?url=${url}&token=${token}`)
    return result.body
}

// get domain information with sublist3r
async function getDomainSub(url){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/sublist3r?url=${url}`)
    return result.body
}

// get domain information with whois
async function getDomainWhoIs(url){
    url = decodeURIComponent(url)
    url = url.split("//")[1]
    if(url[url.length-1] == "/"){
        url = url.slice(0,-1)
    }
    url = encodeURIComponent(url)
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/whois?url=${url}`)
    return result.body
}

// get file and folder with gobuster
async function getDicGobuster(url, token){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/gobuster?url=${url}&token=${token}`)
    return result.body
}

// get technologies of website with whatweb
async function getTechWhatWeb(url,token){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/whatweb?url=${url}&token=${token}`)
    return result.body
}

// get technologies of website with webtech
async function getTechWebTech(url){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/webtech?url=${url}`)
    return result.body
}

// get network information of target url with nmap
async function getServerInfor(url, token){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/nmap?url=${url}&token=${token}`)
    return result.body
}

// detech web firewall
async function getDWab(url, token){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/wafw00f?url=${url}&token=${token}`)
    return result.body
}

// scaning
async function wpScan(url, token){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/wpscan?url=${url}&token=${token}`)
    return result.body
}

async function joomScan(url, token){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/joomscan?url=${url}&token=${token}`)
    return result.body
}

async function droopScan(url, token){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/droopescan?url=${url}&token=${token}`)
    return result.body
}

async function niktoScan(url, token){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/nikto?url=${url}&token=${token}`)

    return result.body
}

// search with searchsploit with source https://www.exploit-db.com/searchsploit
async function searchsploit(pattern){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/searchsploit?pattern=${pattern}`)
    return result.body
}

// search with cve-api with source https://github.com/Beyarz/Cve-api.git
async function search(data){
    let result = await request(`http://${hostCveApi}:${portCveApi}/cve?target=${data.target}&year=${data.year}`)
    let cve = JSON.parse(result.body)
    
    return cve[0]
}

async function addCve(data){
    if (data.technologies==undefined){
        return data
    }

    let temp = data
    for(let i = 0 ; i< temp.technologies.length; i++){
        let result = await request(`http://${hostCveApi}:${portCveApi}/cve?target=${data.technologies[i].name}&year=2021`)
        let cve = JSON.parse(result.body)

        temp.technologies[i]['cve'] = cve[0]
    }
    return temp
}

// Get Vulns from ExploitDB for each technologies which detected by Wappalyzer
async function getVulnsFromExploitDB(data) {
    vulns = []

    if (data.technologies === undefined) {
        return [];

    } else {
        for (let index = 0; index < data.technologies.length; index++) {
            if (data.technologies[index].version !== null && data.technologies[index].version !== "") {
                let results = await searchsploit(data.technologies[index].name + ' ' + data.technologies[index].version);
                results = JSON.parse(results);
                vulns = vulns.concat(results['RESULTS_EXPLOIT'])
            }
        }
    }
    return vulns;
}

// Get vulns for netcraft tool
async function getVulnsForNetcraft(data) {
    vulns = [];

    if (data.technologies == undefined && data['hosting history'] == undefined) {
        return [];

    } else {
        if (data['hosting history'] !== undefined) {
            try {
                let webServerTechs = data['hosting history'][0]['web server'].split(' ');
                for (let index = 0; index < webServerTechs.length; index++) {
                    regex = new RegExp('\/');
                    if (webServerTechs[index].search(regex) !== -1){

                        // Split to get tech and version
                        elements = webServerTechs[index].split('/');

                        let results = await searchsploit(elements[0] + ' ' + elements[1]);
                        results = JSON.parse(results);
                        vulns = vulns.concat(results['RESULTS_EXPLOIT']);
                    }
                }
            } catch {
                return [];
            }
        }

        if (data.technologies !== undefined) {
            vulns = vulns.concat([]);
        }
    }

    return vulns;
}

function readFile(link){
    try {
        let data = fs.readFileSync(link,'utf8')
        return data
    } catch(err){
        console.error(err)
        return ""
    }
}

// format links before handle
function handleLink(str){
    let lastPos=-1
    if (str == undefined){
        return 0
    }
    if (str[str.length-1] != "/"){
        lastPos=str.length
    }
    return str.slice(1,lastPos).split('/')
}

function treeParse(path_str,index=0,path={}){
    // intial value at the first time
    if (path[path_str[index]]==undefined){
        path[path_str[index]] = {}
    }
    let object = path

    // recursion & closure
    function _treeParse(path_str,index=0,path={}){
        if (index+1 >= path_str.length){
            return object
        }
        // intial object or assign 
        let obj = path 


        if (obj[path_str[index]][path_str[index+1]]==undefined){
            obj[path_str[index]][path_str[index+1]] = {}
        } 
    
        index += 1
        return _treeParse(path_str,index,obj[path_str[index-1]]) 
    }

    return _treeParse(path_str,0,path)
}

// get file and folder information with wappalyzer
function createTree(arr){
    let str
    let obj = {}

    for (let i of arr){
        str = handleLink(i)
        obj = treeParse(str,0,obj)
    }
    return obj
}


// Delete all duplicate vulns 
function deleteDuplicate(fieldForFilter, arrayOfObjects) {
    let arr
    try {
        arr = arrayOfObjects.map( (object) => { return [String(object[fieldForFilter] || '').trim(), object] });
    } catch(error){
        console.error(error)
    }
    let mapArr = new Map(arr);
    arrayOfObjects = [...mapArr.values()];
    return arrayOfObjects;
}

async function processVulnsTable(database, token, action, vulns) {

    let currentReport = await database['report'].findOne({token: token});
    let currentVulns = currentReport?.vulns || [];

    if (action === 'add' && vulns) {
        try {
            currentVulns = [...currentVulns, ...vulns];
        } catch {
            currentVulns = vulns?.Title && vulns.Title !== '' ? currentVulns.concat(vulns) : currentVulns;
        }
        currentVulns = deleteDuplicate('Title',currentVulns);
    }

    if (action === 'delete' && vulns && vulns?.Title) {
        let posOfVuln = currentVulns.map((vuln) => { return vuln['Title'] }).indexOf(vulns.Title);
        currentVulns.splice(posOfVuln, 1);
    }

    await database['report'].updateDocument({token: token}, {vulns: currentVulns});
}

// Find the most common element in an array
function fiveMostCommonElements(arrayOfUrls, keyInResult, number) {
    return Object
        .entries(arrayOfUrls
            .reduce((a, v) => {
                a[v] = a[v] ? a[v] + 1 : 1;
                return a;
            }, {})
        )
        .sort((a, b) => { return b[1] - a[1]; })
        .slice(0, number > -1 ? number : this.length)
        .reduce((a, v) => {
            let obj = {};
            obj[keyInResult] = v[0];
            obj['count'] = v[1];
            a.push(obj);
            return a;
        }, []);
}

// Find most common elements in array of objects
function fiveMostCommonObjects(arrayOfElements, fieldFilter, keyInResult, number) {
    let arr = arrayOfElements.map((element) => { return [element[fieldFilter], element]; });
    let mapArr = new Map(arr);

    return Object
        .entries(arrayOfElements
            .reduce((a, v) => {
                a[v[fieldFilter]] = a[v[fieldFilter]] ? a[v[fieldFilter]] + 1 : 1;
                return a;
            }, {})
        )
        .sort((a, b) => { return b[1] - a[1]; })
        .slice(0, number > -1 ? number : this.length)
        .reduce((a, v) => {
            let obj = {};
            obj[keyInResult] = mapArr.get(v[0]);
            obj['count'] = v[1];
            a.push(obj);
            return a;
        }, []);
}

function initializeReport(url, token) {
    let fields = ['url','domain', 'dic', 'dig', 'fierce', 'gobuster', 'server','netcraft','largeio', 'wapp', 'whatweb', 'webtech', 'sublist3r', 'wafw00f', 'droopescan', 'joomscan', 'nikto', 'vulns', 'programing_language','framework','time_create','token'];
    let newReport = {};
    for (let i = 0; i < fields.length; i++) {
        newReport[fields[i]] = {};
    }

    let time = new Date()
    newReport['time_create'] = time

    newReport['url'] = url;
    newReport['token'] = token;

    // Some data need to be an array when initializing
    newReport['vulns'] = [];
    newReport['framework'] = [];
    newReport['programing_language'] = [];

    return newReport;
}

async function updateReport(database, token, tool, data) {
    //Update wapp to report table
    let existReport = await database['report'].findOne({token: token});

    await database['report'].updateDocument({token: token}, {
        [tool]: data
    });
}

async function pullTechnologyFile() {
    try {
        const results = await axios.get('//raw.githubusercontent.com/AliasIO/wappalyzer/master/src/technologies.json');
        let remoteData = results.data;
        if (remoteData && remoteData.technologies && remoteData.categories){
            return remoteData;
        } else {
            throw "Can not get raw file from github";
        }
    } catch {
        try {
            return JSON.parse(fs.readFileSync('/root/wappalyzer/src/technologies.json', 'utf8'));
        } catch {
            return {technologies: [], categories: []};
        }
    }
}

function initializeSearch(url, token) {
  const fields = ['url', 'token', 'operatingsystems', 'webservers', 'webframeworks', 'javascriptframeworks', 'cms', 'programminglanguages'];
  let newSearch = fields.reduce((target, field) => {
      return target[field] = [];
  }, {});
  newSearch['url'] = [url];
  newSearch['token'] = token;
  return newSearch;
}
async function filterDataWapp(dataFromTool) {
  let fields = ['url', 'token', 'operatingsystems', 'webservers', 'webframeworks', 'javascriptframeworks', 'cms', 'programminglanguages'];
  let techData = dataFromTool?.technologies || [];

  let search_results = techData
    .map(techDatumn => ({
      technology: techDatumn?.version ? techDatumn.name + '/' + techDatumn.version : techDatumn.name,
      category: techDatumn.categories[0].name.toLowerCase().replace(/\s+/g, '')
    }))
    .filter(({category}) => fields.includes(category))
    .reduce((result, {technology, category}) => ({
        ...result, [category]: [...(result[category] || []), technology]
    }), {});

  search_results['token'] = dataFromTool['token'];
  search_results['url'] = dataFromTool['url'];
  
  return search_results;

}

// Filter data for search table
async function filterDataTool(dataFromTool) {
    let fields = ['url', 'token', 'operatingsystems', 'webservers', 'webframeworks', 'javascriptframeworks', 'cms', 'programminglanguages'];
    let techData = dataFromTool && 
        dataFromTool.technologies && 
        dataFromTool.technologies !== 'a' ? dataFromTool.technologies : [];

    let technologiesFile = await pullTechnologyFile();
    let technologies = technologiesFile.technologies;
    let categories = technologiesFile.categories;

    const technologyNames = Object.keys(technologies).map(name => name.toLowerCase());

    let search_results = techData
        .filter(({name}) => technologyNames.includes(name.toLowerCase().trim()))
        .reduce((result, technology) => {
            const technologyName = Object.keys(technologies).find(item => technology.name.toLowerCase().trim() === item.toLowerCase());
            result.push([technologyName, technology?.version ? technology.version : '']);
            return result;
        }, [])
        .map(technology => {
        const category = technologies[technology[0]].cats[0];
        return {
            technology: technology[1] ? technology[0] + '/' + technology[1] : technology[0],
            category: categories[category].name.toLowerCase().replace(/\s+/, '')
        }})
        .filter(({category}) => fields.includes(category))
        .reduce((result, {technology, category}) => ({
        ...result, [category]: [...(result[category] || []), technology]
        }), {})

        if (Object.keys(dataFromTool).includes('hosting history')) {
            if (dataFromTool['hosting history'].length !== 0 && dataFromTool['hosting history'] !== 'Can not load Uptime data') {
                search_results['webservers'] = [...(search_results['webservers'] || []), (dataFromTool['hosting history'][0]['web server'] || null)];
                search_results['operatingsystems'] = [...(search_results['operatingsystems'] || []), (dataFromTool['hosting history'][0]['os'] || null)];
            }
        }
        search_results['token'] = dataFromTool['token'];
        search_results['url'] = dataFromTool['url'];
    return search_results;
}

async function searchInSearchTable(database, pattern) {
    const  fields = ['url', 'token', 'operatingsystems', 'webservers', 'webframeworks', 'javascriptframeworks', 'cms', 'programminglanguages'];
    const regex = new RegExp(pattern, 'gi');
  
    let results = await Promise.all(fields
      .filter(field => field !== 'token')
      .map(async (field) => {
        const resultFromSearch = await database['search'].elementMatch(field, {$regex: regex});
        return resultFromSearch;
      }));
    
    results = results.reduce((current, item) => {
        return current.concat(item);
    }, []);

    results = await Promise.all(results.map(async (item) => {
        const reportFromToken = await database['report'].findOne({token: item.token});
        return reportFromToken;
    }));

    return results;
}
async function searchInReportTable(database, pattern) {
  let fields = ['url', 'domain', 'dic', 'dig', 'fierce', 'gobuster', 'server', 'netcraft', 'largeio', 'wapp', 'whatweb', 'webtech', 'sublist3r', 'wafw00f', 'droopescan', 'joomscan', 'nikto', 'vulns', 'programing_language', 'framework', 'time_create'];
  const regex = new RegExp(pattern, 'gi');

  // Get all reports from databases
  const allReportsFromDatabase = await database['report'].getTable({});
  
  let results = allReportsFromDatabase
    .reduce((current, report) => {
        const finalResult = fields.reduce((current, field) => {
           const fieldContent = JSON.stringify(!report[field] ? [] : report[field]);
           return fieldContent.search(regex) < 0 ? current + 0 : current + 1;
        }, 0);
        return finalResult > 0 ? current.concat(report) : current.concat([]);
    }, []);
  return results;
}

async function updateSearchTable(database, searchData) {
    let fields = ['operatingsystems', 'webservers', 'webframeworks', 'javascriptframeworks', 'cms', 'programminglanguages'];
    const targetExist = await database['search'].findOne({token: searchData.token});
    const finalResult = fields
        .filter((field) => Object.keys(searchData).includes(field))
        .reduce((current, field) => {
            current[field] = [...new Set([...(current[field] || []),...(targetExist[field] || []),...searchData[field]])];
            return current;
        }, {});

    await database['search'].updateDocument({token: searchData.token}, finalResult);

}

async function getNumAndRatio(database, type) {
    const fieldFilter = type === 'language' ? 'programminglanguages' : 'webframeworks';
    const keyInResult = type === 'language' ? 'programing_language' : 'framework';

    const searchData = await database['search'].getTable({});

    let elementsList = searchData
        .map((item) => {
            let elements = item[fieldFilter].map((language) => language.split('/')[0]);
            return [...new Set(elements)]
        })
        .reduce((result, searchRecord) => ([
            ...result, ...searchRecord
        ]), [])
    
    const num = [...new Set(elementsList)].length.toString();
    const ratio = fiveMostCommonElements(elementsList, keyInResult, 5);

    return [num, ratio];
}

async function numberOfReport (database) {
    let listReport = await database['report'].getTable({})
    return listReport.length.toString();
}

async function numberOfVuln(database) {
    let arrayOfReports = await database['report'].getTable({});

    let arrayOfVulns = arrayOfReports.reduce((result, report) => {
        return result.concat(report.vulns);
    }, []);

    arrayOfVulns = deleteDuplicate('Title', arrayOfVulns);
    
    return arrayOfVulns.length.toString();
}

async function topFiveElement(type, database) {
    // Get all reports from database
    let arrayOfReports = await database['report'].getTable({});
    // Check if reports array is empty
    if (arrayOfReports.length === 0){
        return [];
    } else {
        // If type is url
        if (type === 'url') {
            let arrayOfUrls = arrayOfReports.reduce((result, report) => { 
                result.push(report.url);
                return result;
            }, []);

            return fiveMostCommonElements(arrayOfUrls, 'url', 5);
        }
        // If type is vuln
        if (type === 'vuln') {
           let arrayOfVulns = arrayOfReports.reduce((resultAllReports, report) => {
                return resultAllReports.concat(report.vulns);
            }, []);

            return fiveMostCommonObjects(arrayOfVulns, 'Title', 'vuln', 5);
        }
        // If type is waf
        if (type === 'waf') {
            let listWafsEachReport = [];
            let arrayOfWafs = arrayOfReports.reduce((result, report) => {
                listWafsEachReport = (report.wafw00f?.waf || []).reduce((a, v) => {
                    if (v.firewall !== 'None'){
                        a.push(v);
                    }
                    return a;
                },[]);

                return (result.concat(listWafsEachReport));

            }, []);

            return fiveMostCommonObjects(arrayOfWafs, 'firewall', 'waf', 5);
        }
    }
}

function stopAllTools(token) {
    result = request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/stop_all_tools?token=${token}`)
}

module.exports = addCve
module.exports.getVulnsFromExploitDB = getVulnsFromExploitDB
module.exports.getVulnsForNetcraft = getVulnsForNetcraft
module.exports.deleteDuplicate = deleteDuplicate
module.exports.processVulnsTable = processVulnsTable
module.exports.initializeReport = initializeReport
module.exports.updateReport = updateReport
module.exports.initializeSearch = initializeSearch
module.exports.updateSearchTable = updateSearchTable
module.exports.filterDataTool = filterDataTool
module.exports.filterDataWapp = filterDataWapp
module.exports.searchInReportTable = searchInReportTable
module.exports.searchInSearchTable = searchInSearchTable
module.exports.stopAllTools = stopAllTools
// module.exports.calRunTime = calRunTime

module.exports.search = search
module.exports.treeParse = treeParse
module.exports.handleLink = handleLink
module.exports.createTree = createTree
module.exports.getDnsDig = getDnsDig
module.exports.getDnsFierce = getDnsFierce
module.exports.getDomainSub = getDomainSub
module.exports.getDomainWhoIs = getDomainWhoIs
module.exports.getServerInfor = getServerInfor
module.exports.getDicGobuster = getDicGobuster
module.exports.getTechWhatWeb = getTechWhatWeb
module.exports.getTechWebTech = getTechWebTech
module.exports.getDWab = getDWab
module.exports.wpScan = wpScan
module.exports.droopScan = droopScan
module.exports.niktoScan = niktoScan
module.exports.joomScan = joomScan
module.exports.searchsploit = searchsploit
module.exports.createTree = createTree
module.exports.checkCms = checkCms
module.exports.readFile = readFile
module.exports.takeScreenshot = takeScreenshot
module.exports.getHostFromUrl = getHostFromUrl

module.exports.getNumAndRatio = getNumAndRatio
module.exports.numberOfReport = numberOfReport
module.exports.numberOfVuln = numberOfVuln
module.exports.topFiveElement = topFiveElement

module.exports.hostDatabase = hostDatabase
module.exports.portDatabase = portDatabase