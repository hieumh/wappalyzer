const request = require('async-request')
const { technologies } = require('./wappalyzer')
const fs = require('fs')

let hostDatabase = "172.17.0.2"
let portDatabase ="27017"

let hostCveApi = "172.17.0.3"
let portCveApi = "4000"

let hostServerApi = "172.17.0.4"
let portServerApi = "5000"

let programingLanguage = readFile("./alphabet_programing_language/language.txt").split("\n").map(element=>element.trim().toLowerCase())

let framework = readFile("./alphabet_programing_language/framework.txt").split("\n").map(element=>element.trim().toLowerCase())

async function checkCms(url){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/cmseek?url=${url}`)
    return result.body
}

// get dns information
async function getDnsDig(url){
    url = url.split("//")[1]
    if(url[url.length-1] == "/"){
        url = url.slice(0,-1)
    }
    
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
    url = url.split("//")[1]
    if(url[url.length-1] == "/"){
        url = url.slice(0,-1)
    }
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/whois?url=${url}`)
    return result.body
}

// get file and folder with gobuster
async function getDicGobuster(url){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/gobuster?url=${url}`)
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

async function joomScan(url){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/joomscan?url=${url}`)
    return result.body
}

async function droopScan(url){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/droopescan?url=${url}`)
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
        path[path_str[index]] = JSON.stringify({})
    }
    let object = path

    // recursion & closure
    function _treeParse(path_str,index=0,path={}){
        if (index+1 >= path_str.length){
            return object
        }
        // intial object or assign value
        if (path[path_str[index]][path_str[index+1]]==undefined){
            path[path_str[index]][path_str[index+1]] = JSON.stringify({})
        } 
    
        index += 1
        return _treeParse(path_str,index,path[path_str[index-1]]) 
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


// Find the most common element in an array
function fiveMostCommonUrls(arrayOfUrls) {
    // Generate an array of arrays which have this format [ [element, occurences],...]
    return Object.entries(arrayOfUrls.reduce((a, v) => {
            a[v] = a[v] ? a[v] + 1 : 1;
            return a;
        }, {})).sort((a, b) => { 
            return b[1] - a[1];
        }).slice(0, 5).reduce((a, v) => {
            let obj = {};
            obj['url'] = v[0];
            obj['count'] = v[1];
            a.push(obj);
            return a;
        }, [])
}

function fiveMostCommonVulns(arrayOfVulns) {
    let arr = arrayOfVulns.map((vuln) => { return [vuln.Title, vuln]; });
    let mapArr = new Map(arr);
    let topFive = Object.entries(arrayOfVulns.reduce((a, v) => {
        a[v.Title] = a[v.Title] ? a[v.Title] + 1 : 1;
        return a;
    }, {})).sort((a,b) => {
        return b[1] - a[1];
    }).slice(0, 5).reduce((a, v) => {
        let obj = {};
        obj['vuln'] = mapArr.get(v[0]);
        obj['count'] = v[1];
        a.push(obj);
        return a;
    }, []);

    return topFive;
}


function filterLanguage(techsInDatabase){
    // [{name:php,..},{name:python,...},{},...]
    return techsInDatabase.filter(tech=>{
        return programingLanguage.includes(tech.name.toLowerCase())
    })
}

function filterFramework(techsInDatabase){
    return techsInDatabase.filter(tech=>{
        return framework.includes(tech.name.toLowerCase())
    })
}

function intersectionList(listA, listB){
    let tempA = listA ? listA : []
    let tempB = listB ? listB : []

    if(!(tempA.length + tempB.length)){
        return []
    }

    let unionList = [...tempA,...tempB]
    let intersecListKeys = {}
    let result = []

    for (let element of unionList){
        intersecListKeys[element] = true
    }

    for (let name in intersecListKeys){
        result.push(name)
    }
    return result
}

function countExist(unionList){
    if(!unionList.length){
        return []
    }

    let objCount = {}
    let result = []

    for (let element of unionList){
        objCount[element]={}
        objCount[element]['count'] = objCount[element]['count'] === undefined ? 1 : objCount[element]['count']+1
    }

    for (let key in objCount){
        let temp = {}
        temp['language'] = key
        temp['count'] = objCount[key]['count']

        result.push(temp)
    }
    return result
}

function intersectionListObject(key,listA=[],listB=[],listC=[],listD=[],listE=[]){
    if(!key){
        return []
    }
    let tempA = listA ? listA : []
    let tempB = listB ? listB : []
    let tempC = listC ? listC : []
    let tempD = listD ? listD : []
    let tempE = listE ? listE : []

    let unionList = [...tempA,...tempB,...tempC,...tempD,...tempE]
    let intersecListKeys = {}
    let result = []

    for (let obj of unionList){
        intersecListKeys[obj[key]] = true
    }

    for (let name in intersecListKeys){
        result.push(name)
    }
    return result
}

module.exports = addCve
module.exports.getVulnsFromExploitDB = getVulnsFromExploitDB
module.exports.getVulnsForNetcraft = getVulnsForNetcraft
module.exports.fiveMostCommonUrls = fiveMostCommonUrls
module.exports.fiveMostCommonVulns = fiveMostCommonVulns

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
module.exports.filterLanguage = filterLanguage
module.exports.filterFramework =filterFramework
module.exports.intersectionListObject = intersectionListObject
module.exports.intersectionList = intersectionList
module.exports.countExist = countExist

module.exports.hostDatabase = hostDatabase
module.exports.portDatabase = portDatabase
