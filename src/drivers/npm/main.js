// chịu trách nhiệm phân tích tất cả các route trên
'use strict'
//const cli = require('./cli')
const fs = require('fs')
const startWep = require('./cli')
const express = require('express')
const bodyParser = require('body-parser')
const databaseHandle = require('./database')
const addCve = require('./lib')
const {search,
    getVulnsForNetcraft,
    getVulnsFromExploitDB,
    createTree,
    getDnsDig,
    getDnsFierce,
    getDomainSub,
    getDomainWhoIs,
    getServerInfor,
    getDicGobuster,
    getTechWhatWeb,
    getTechWebTech,
    getDWab,
    wpScan,
    droopScan,
    joomScan,
    niktoScan,
    checkCms,
    searchSploit,
    deleteDuplicate,
    fiveMostCommonUrls,
    fiveMostCommonVulns,
    filterFramework,
    filterLanguage,
    intersectionListObject,
    intersectionList
} = require('./lib')
const netcraft = require("./tools/netcrafts/netcraft")
const largeio = require("./tools/largeio/largeio")

// Add uuidv
const uuidv4 = require('uuid')
const { ServerResponse } = require('http')
const { technologies } = require('./wappalyzer')

const database = {'wapp':null,'link':null}
database['wapp'] = new databaseHandle('wapp')
database['netcraft'] = new databaseHandle('netcraft')
database['largeio'] = new databaseHandle('largeio')
database['whatweb'] = new databaseHandle('whatweb')
database['webtech'] = new databaseHandle('webtech')

database['link'] = new databaseHandle('link')
database['dic'] = new databaseHandle('dic')
database['gobuster'] = new databaseHandle('gobuster')

database['whois'] = new databaseHandle('whois')
database['sublist3r'] = new databaseHandle('sublist3r')

database['dig'] = new databaseHandle('dig')
database['fierce'] = new databaseHandle('fierce')

database['server'] = new databaseHandle('server')

database['wafw00f'] = new databaseHandle('wafw00f')

database['wpscan'] = new databaseHandle('wpscan')
database['droopescan'] = new databaseHandle('droopescan')
database['joomscan'] = new databaseHandle('joomscan')
database['nikto'] = new databaseHandle('nikto')

// Create vuln collection
database['vuln'] = new databaseHandle('vuln');
database['report'] = new databaseHandle('report')


const app = express()
app.use(bodyParser.json({limit:'50mb'}))
app.use(bodyParser.urlencoded({
    extended:false,
    limit:"50mb"
}))

app.use((req,res,next) =>{
    res.append('Access-Control-Allow-Origin',"*")
    res.append('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.append("Access-Control-Allow-Credentials", 'true');
    res.append('Access-Control-Allow-Headers', 'Origin,Content-Type,Cache-Control,Authorization');
    next();
})

// app.get('/*', (req, res) => {
//     res.sendFile(path.join(__dirname, 'build', 'index.html'))
// })

// Token generator
app.get("/token/generator", (req, res) => {
    let token = uuidv4();
    res.send(token)
});

// get result analyzed in database
app.get("/url_analyze/:tool",async (req,res)=>{
    let {tool} = req.params
    let {token} = req.query

    let result = await database[tool].findOne({token:token})
    res.send(result)
})

// test cms technologies
app.post("/url_analyze/cmseek",async (req,res)=>{
    let {url} = req.body

    try {
        let result = await checkCms(url)
        result = JSON.parse(result)
        res.send(result)
    } catch(err){
        console.error(err)
        res.status(500)
        res.send(err)
    }
})

///////////////////////////////////////////////////////////////
// analyze technologies for url
app.post('/url_analyze/wapp',async (req,res)=>{
    let {url} = req.body

    let token = req.body.token;


    // wait for analyze successfully
    let check = await startWep(database,url, token)

    // data saved in database, and get it from database
    let dataSend = await database['wapp'].findOne({token:token})
    
    await processVulnsTable(token, 'add', dataSend['vulns']);

    res.send(dataSend)
})

app.post('/url_analyze/netcraft', async (req,res)=>{
    let {url} = req.body

    // Get token from request
    let token = req.body.token;

    let dataRecv = await netcraft.netcraft(url)
    try {
        dataRecv = JSON.parse(dataRecv)
    } catch (err){
        console.error(err)
    }

    let dataSend = await addCve({
        url:url,
        technologies:dataRecv.technologies
    })

    dataSend['programing_language'] = filterLanguage(dataSend['technologies'])
    dataSend['framework'] = filterFramework(dataSend['technologies'])
    dataSend['token'] = token
    dataSend['vulns'] = await getVulnsForNetcraft(dataRecv);

    // Add vulns to Vulns Table
    await processVulnsTable(token, 'add', dataSend['vulns']);

    await database['netcraft'].add(dataSend)
    res.send(dataSend)
})

app.post('/url_analyze/largeio', async (req,res)=>{
    let {url, options} = req.body

    // Get token from request
    let token = req.body.token;

    let dataRecv = await largeio.largeio(url)
    try {
        dataRecv = JSON.parse(dataRecv)
    } catch (err){
        console.error(err)
    }

    let tech
    if(JSON.stringify(dataRecv.technologies) === "[]" || !dataRecv.technologies){
        tech = []   
    } else {
        tech = dataRecv.technologies
    }

    let dataSend = await addCve({
        url:url,
        technologies:tech
    })

    dataSend['programing_language'] = filterLanguage(dataSend['technologies'])
    dataSend['framework'] = filterFramework(dataSend['technologies'])
    dataSend['token'] = token
    dataSend['vulns'] = await getVulnsFromExploitDB(dataRecv);

    // Add vulns to Vulns Table
    await processVulnsTable(token, 'add', dataSend['vulns']);
    
    await database['largeio'].add(dataSend)
    res.send(dataSend)
})

app.post('/url_analyze/whatweb', async (req,res)=>{
    let {url, options} = req.body

    let token = req.body.token;

    let dataRecv = await getTechWhatWeb(url,token)
    try {
        dataRecv = JSON.parse(dataRecv)
    } catch (err){
        console.error(err)
    }
    
    let tech
    if(JSON.stringify(dataRecv.technologies) === "[]" || !dataRecv.technologies){
        tech = []
    } else {
        tech = dataRecv.technologies
    }

    let dataSend = await addCve({
        url:url,
        technologies:tech
    })
    
    dataSend['programing_language'] = filterLanguage(dataSend['technologies'])
    dataSend['framework'] = filterFramework(dataSend['technologies'])
    dataSend['token'] = token
    dataSend['vulns'] = dataRecv['vulns'];

    // Add vulns to Vulns Table
    await processVulnsTable(token, 'add', dataSend['vulns']);
    
    await database['whatweb'].add(dataSend)
    res.send(dataSend)
})

app.post('/url_analyze/webtech', async (req,res)=>{
    let {url, options} = req.body

    let token = req.body.token;

    let dataRecv = await getTechWebTech(url)
    try {
        dataRecv = JSON.parse(dataRecv)
    } catch (err){
        console.error(err)
    }

    let tech
    if(JSON.stringify(dataRecv.technologies) === "[]" || !dataRecv.technologies){
        tech = []
    } else {
        tech = dataRecv.technologies
    }

    let dataSend = await addCve({
        url:url,
        technologies:tech
    })
    
    dataSend['programing_language'] = filterLanguage(dataSend['technologies'])
    dataSend['framework'] = filterFramework(dataSend['technologies'])
    dataSend['token'] = token
    dataSend['vulns'] = dataRecv['vulns'];

    // Add vulns to Vulns Table
    await processVulnsTable(token, 'add', dataSend['vulns']);

    await database['webtech'].add(dataSend)
    res.send(dataSend)
})
////////////////////////////////////////////////////




////////////////////////////////////////////////////
// analyze directory and file enumeration
app.post('/url_analyze/dic',async (req,res)=>{
    let {url} = req.body

    let token = req.body.token;

    // get link from database
    let result = await database['link'].findOne({url:url})

    let arr = []
    let hostname = url.split("//")[1]
    hostname = hostname.split("/")[0]

    result.links.forEach(ele =>{
        if(hostname == ele.hostname){
            arr.push(ele.pathname)
        }
    })

    // save to database
    let tree = createTree(arr)
    delete Object.assign(tree, {["/"]: tree[""] })[""];
    tree = new Object(tree)
    
    let dataSave = {
        url:url,
        token: token,
        trees:tree
    }

    let dataResult = await database['dic'].add(dataSave)

    res.send(dataResult)
})


app.post('/url_analyze/gobuster', async (req,res)=>{
    let {url} = req.body

    let token = req.body.token;

    let dataRecv = await getDicGobuster(url)
    if (dataRecv == "Wrong URL"){
        dataRecv = {}
    }
    try {
        dataRecv = JSON.parse(dataRecv)
    } catch (err){
        console.error(err)
    }

    // add to database
    let dataSend = {
        url:url,
        gobuster:dataRecv,
        token: token
    }
    dataSend = await database['gobuster'].add(dataSend)

    res.send(dataSend)
})
///////////////////////////////////////////////////




///////////////////////////////////////////////////
// analyze dns information 
app.post('/url_analyze/dig',async (req,res)=>{
    let {url,token} = req.body

    let dnsInfor = await getDnsDig(url)

    let dataSend 
    try {
        dataSend = await database['dig'].add({
            url:url,
            dns:dnsInfor,
            token: token
        })
    } catch(err){
        console.error(err)
    }
    
    res.send(dataSend)
})

app.post('/url_analyze/fierce', async (req,res)=>{
    let {url,token} = req.body

    let dnsInfor = await getDnsFierce(url, token)

    let dataSend = await database['fierce'].add({
        url:url,
        dns:dnsInfor,
        token: token
    })
    res.send(dataSend)
})
///////////////////////////////////////////////////




///////////////////////////////////////////////////
// analyze information for domain
app.post('/url_analyze/whois', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let domainInfor = await getDomainWhoIs(url)
    try {
        domainInfor = JSON.parse(domainInfor)
    } catch (err){
        console.error(err)
    }

    let keys = Object.keys(domainInfor)
    for(let key of keys){
        if(!Array.isArray(domainInfor[key])){
            domainInfor[key] = new Array(domainInfor[key])
        }
    }

    let dataSend = await database['whois'].add({
        url:url,
        domains:domainInfor,
        token: token
    })
    res.send(dataSend)
})

app.post('/url_analyze/sublist3r', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let domainInfor = await getDomainSub(url)
    try {
        domainInfor = JSON.parse(domainInfor)
    } catch (err){
        console.error(err)
    }

    let dataSend = await database['sublist3r'].add({
        url:url,
        domains:domainInfor.subdomains,
        token: token
    })    
    res.send(dataSend)
})
/////////////////////////////////////////////////////




/////////////////////////////////////////////////////
// server information (using nmap information)
app.post('/url_analyze/server', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let serverInfor = await getServerInfor(url, token)
    try{
        serverInfor = JSON.parse(serverInfor);
    } catch(error) {
        console.log(error);
    }

    await database['server'].add({
        url:url,
        server:serverInfor['nmap'],
        token: token,
        vulns: serverInfor['vulns']
    })

    // Add vulns to Vulns Table
    await processVulnsTable(token, 'add', serverInfor['vulns']);

    res.send(serverInfor)
})
/////////////////////////////////////////////////////




////////////////////////////////////////////////////
// Detect web firewall
app.post('/url_analyze/wafw00f', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let detectWaf = await getDWab(url)
    try {
        detectWaf = JSON.parse(detectWaf)
    } catch(err){
        console.error(err)
    }

    await database['wafw00f'].add({
        url:url,
        waf:detectWaf.wafs,
        token: token
    })
    res.send(detectWaf)
})
///////////////////////////////////////////////////





////////////////////////////////////////////////////
// scanning
app.post('/url_analyze/wpscan', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let wp = await wpScan(url, token)

    await database['wpscan'].add({
        url:url,
        wp:wp,
        token: token,
        vulns: wp['vulns']
    })

    // Add vulns to Vulns Table
    await processVulnsTable(token, 'add', wp['vulns']);

    res.send(wp)
})

app.post('/url_analyze/droopescan', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let droope = await droopScan(url)

    await database['droopescan'].add({
        url:url,
        droope:droope,
        token: token,
        vulns: droope['vulns']
    })


    // Add vulns to Vulns Table
    await processVulnsTable(token, 'add', droope['vulns']);

    res.send(droope)


})

app.post('/url_analyze/joomscan', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let joomscan = await joomScan(url)

    await database['joomscan'].add({
        url:url,
        joomscan:joomscan,
        token: token,
        vulns: joomscan['vulns']
    })

    // Add vulns to Vulns Table
    await processVulnsTable(token, 'add', joomscan['vulns']);

    res.send(joomscan)
})

app.post('/url_analyze/nikto', async (req,res)=>{
    let {url} =  req.body
    let token = req.body.token;

    let nikto = await niktoScan(url, token)

    await database['nikto'].add({
        url:url,
        nikto:nikto,
        token: token,
        vulns: nikto['vulnerabilities']
    })

    // Add vulns to Vulns Table
    // await processVulnsTable(token, 'add', nikto['vulnerabilities']);

    res.send(nikto)
})
///////////////////////////////////////////////////


////////////////////////////////////////////////////
app.get('/history', async (req,res)=>{
    let dataSend = await database['report'].getTable({})
    res.send(dataSend)
})
////////////////////////////////////////////////////


//////////////////////////////////////////////////////////////////
app.get('/search_database', async (req, res) => {
    let fields = ['url','wapp', 'whatweb', 'webtech', 'dic', 'sublist3r', 'wafw00f', 'droopescan', 'joomscan', 'domain', 'nikto', 'dns','gobuster', 'domain', 'server','netcraft','largeio'];
    
    // Pre-process pattern
    let pattern = req.query.pattern;
    if (!pattern) {
        res.send([]);
    } else {

        // Delete all begining and ending space
        pattern = pattern.trim();
        if (pattern === '') {
            res.send([]);
        } else {
            // Find all spaces in pattern parameter and replace them with "|"
            let regex = new RegExp('\\s+', 'g');
            pattern = `(${pattern.replaceAll(regex, '|')})`

            // Return _id to front-end
            let results = [];

            // Get all reports from databases
            let allReportsFromDatabase = await database['report'].getTable({});

            for (let index = 0; index < allReportsFromDatabase.length; index++) {

                for (let field in fields) {

                    // Convert content of each field to string for searching
                    let fieldContent = JSON.stringify(allReportsFromDatabase[index][fields[field]]);
                    
                    let searchResult
                    regex = new RegExp(pattern, 'g');
                    try{
                        searchResult = fieldContent.search(regex);
                    } catch {
                        searchResult = -1
                    }

                    if (searchResult !== -1){
                        results.push(allReportsFromDatabase[index]);
                    }
                }
            }

            // Delete dumplicate elements in results
            results = deleteDuplicate('_id', results);
            res.send(results);
        }
        
    }
});

// Process Vulns Table with load, add, or delete
async function processVulnsTable(token, action, vulns) {

    let currentTable = await database['vuln'].findOne({token: token});
    let currentVulns = currentTable ? currentTable['vulns'] : [];

    if (action === 'add') {
        currentVulns = currentVulns.concat(vulns);
        currentVulns = deleteDuplicate('Title',currentVulns);
    }

    if (action === 'delete') {
        let posOfVuln = currentVulns.map((vuln) => { return vuln['Title'] }).indexOf(vulns.Title);
        currentVulns.splice(posOfVuln, 1);
    }
    
    // Decide first time or many times which adding vulns to database
    if (!currentTable) {
        await database['vuln'].add({token: token, vulns: currentVulns});
    } else {
        let id = currentTable._id;
        let check = await database['vuln'].replaceDocument({_id: id}, {token: token, vulns: currentVulns});
    }
}

app.post('/update_vulns_table', async(req, res) => {
    
    let {token, action, vulns} = req.body;
    await processVulnsTable(token, action, vulns);
    
    let vulnTable = await database['vuln'].getTable({token: token});

    res.send(vulnTable[0]);
});

// create report (base on the last result of each table)
app.post("/create_report",async (req,res)=>{
    let data = {}
    let url = req.body.url
    let token = req.body.token

    await database['wapp'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['wapp'] = result[0] ? result[0] : "";
    })
    await database['whatweb'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['whatweb'] = result[0] ? result[0] : "";
        
    })
    await database['webtech'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['webtech'] = result[0] ? result[0] : "";

    })
    await database['netcraft'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['netcraft'] = result[0] ? result[0] : "";

    })
    await database['largeio'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['largeio'] = result[0] ? result[0] : "";

    })
    
    await database['dic'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['dic'] = result[0] ? result[0] : ""
    })
    await database['gobuster'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['gobuster'] = result[0] ? result[0] : ""
    })

    await database['whois'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['whois'] = result[0] ? result[0] : ""
    })
    await database['sublist3r'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['sublist3r'] = result[0] ? result[0] : ""
    })

    await database['dig'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['dns'] = result[0] ? result[0] : ""
    })
    await database['fierce'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['dns'] = result[0] ? result[0] : ""
    })

    await database['server'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['server'] = result[0] ? result[0] : "";
    })
    
    await database['wafw00f'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['wafw00f'] = result[0] ? result[0] : ""
    })

    await database['wpscan'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['wpscan'] = result[0] ? result[0] : "";
    })
    await database['droopescan'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['droopescan'] = result[0] ? result[0] : "";
    })

    await database['joomscan'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['joomscan'] = result[0] ? result[0] : "";
    })

    await database['nikto'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['nikto'] = result[0] ? result[0] : ""
    })

    await database['vuln'].getTable({token: token}, {_id: 0, token: 0}).then((result) => {
        data['vulns'] = result[0] ? [...result[0].vulns] : ""
    })

    data['url'] = url

    let time = new Date()
    data['time_create'] = time

    data['token'] = token;
    data['programing_language'] = intersectionListObject("name",data['wapp']['programing_language'],data['netcraft']['programing_language'],data['largeio']['programing_language'],data['webtech']['programing_language'],data['whatweb']['programing_language'])
    data['framework'] = intersectionListObject("name",data['wapp']['framework'],data['netcraft']['framework'],data['largeio']['framework'],data['webtech']['framework'],data['whatweb']['framework'])

    await database['report'].add(data)

    res.send("create database success")
})

app.get('/dashboard/num_report', async (req,res)=>{
    let listReport = await database['report'].getTable({})
    res.send(listReport.length.toString())
})

app.get('/dashboard/num_tech', async (req,res)=>{
    let listReport = await database['report'].getTable({})

    let intersecList = []
    for (let report of listReport){
        intersecList = intersectionList(intersecList, report['programing_language'])
    }
    
    res.send(intersecList.length.toString())
})

app.get('/dashboard/num_framework', async (req,res)=>{
    let listReport = await database['report'].getTable({})

    let intersecList = []
    for (let report of listReport){
        intersecList = intersectionList(intersecList, report['framework'])
    }
    res.send(intersecList.length.toString())
})

app.get('/dashboard/num_vuln', async (req, res) => {
    let arrayOfReports = await database['report'].getTable({});

    let arrayOfVulns = arrayOfReports.reduce((result, report) => {
        return result.concat(report.vulns);
    }, []);

    arrayOfVulns = deleteDuplicate('Title', arrayOfVulns);
    
    res.send(arrayOfVulns.length.toString());
});

app.get("/dashboard/language_ratio",async (req,res)=>{
    let listReport = await database['report'].getTable({})

    let unionList = []
    for (let report of listReport){
        unionList.push(...report["programing_language"])
    }

    let dataSend = countExist(unionList)
    res.send(dataSend)
})

app.get('/dashboard/get_five_most_common', async (req, res) => {
    // Get the most common of url or vuln ?
    let {type} = req.query;
    // Get all reports from database
    let arrayOfReports = await database['report'].getTable({});
    // Check if reports array is empty
    if (arrayOfReports.length === 0){
        res.send([]);
    } else {
            // If type is url
        if (type === 'url') {
            let arrayOfUrls = arrayOfReports.reduce((result, report) => { 
                result.push(report.url);
                return result;
            }, []);

            res.send(fiveMostCommonUrls(arrayOfUrls));
        }
        // If type is vuln
        if (type === 'vuln') {
           let arrayOfVulns = arrayOfReports.reduce((resultAllReports, report) => {
                return resultAllReports.concat(report.vulns);
            }, []);

            res.send(fiveMostCommonVulns(arrayOfVulns));
        }
    }
});

app.listen(3000, () => {
    console.log("Server is running on port 3000")
})

