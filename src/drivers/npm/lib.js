const request = require('async-request')
const { technologies } = require('./wappalyzer')

let hostDatabase = "172.17.0.3"
let portDatabase ="27017"

let hostCveApi = "172.17.0.4"
let portCveApi = "4000"

let hostServerApi = "172.17.0.5"
let portServerApi = "5000"

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

async function getDnsFierce(url){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/fierce?url=${url}`)
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
async function getServerInfor(url){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/nmap?url=${url}`)
    return result.body
}

// detech web firewall
async function getDWab(url){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/wafw00f?url=${url}`)
    return result.body
}

// scaning
async function wpScan(url){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/wpscan?url=${url}`)
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

async function niktoScan(url){
    let result = await request(`http://${hostServerApi}:${portServerApi}/api/v1/enumeration/nikto?url=${url}`)

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

function createFile(jsonInput){

}

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


module.exports = addCve
module.exports.getVulnsFromExploitDB = getVulnsFromExploitDB
module.exports.getVulnsForNetcraft = getVulnsForNetcraft

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
module.exports.createFile = createFile
module.exports.checkCms = checkCms

module.exports.hostDatabase = hostDatabase
module.exports.portDatabase = portDatabase
