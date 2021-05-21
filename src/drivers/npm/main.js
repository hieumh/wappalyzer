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
    createFile,
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
    searchSploit
} = require('./lib')
const netcraft = require("./tools/netcrafts/netcraft")
const largeio = require("./tools/largeio/largeio")

// Add uuidv
const uuidv4 = require('uuid')
const { ServerResponse } = require('http')

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
        // console.log(url, result)
        res.send(result)
    } catch(err){
        console.log(err)
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
    
    if(!check){
        console.log("error")
    } else {
        console.log("add success")
    }

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
        console.log(err)
    }

    let dataSend = await addCve({
        url:url,
        technologies:dataRecv.technologies
    })

    // Add token to result
    dataSend['token'] = token

    // Add vulns to result
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
        console.log(err)
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
    
    // Add token to result
    dataSend['token'] = token

    // Add vulns to result
    dataSend['vulns'] = await getVulnsFromExploitDB(dataRecv);

    // Add vulns to Vulns Table
    await processVulnsTable(token, 'add', dataSend['vulns']);
    
    await database['largeio'].add(dataSend)
    res.send(dataSend)
})

app.post('/url_analyze/whatweb', async (req,res)=>{
    let {url, options} = req.body

    let token = req.body.token;

    let dataRecv = await getTechWhatWeb(url)
    try {
        dataRecv = JSON.parse(dataRecv)
    } catch (err){
        console.log(err)
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
        console.log(err)
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
    
    let dataResult = await database['dic'].add({
        url:url,
        dic:tree,
        token: token
    })

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
        console.log(err)
    }

    // add to database
    let dataSend = {
        url:url,
        gobuster:dataRecv,
        token: token
    }
    await database['gobuster'].add(dataSend)
    res.send(dataSend)
})
///////////////////////////////////////////////////




///////////////////////////////////////////////////
// analyze dns information 
app.post('/url_analyze/dig',async (req,res)=>{
    let {url,token} = req.body

    let dnsInfor = await getDnsDig(url)
    try {
        dnsInfor = JSON.parse(dnsInfor)
    } catch (err){
        console.log(err)
    }


    await database['dig'].add({
        url:url,
        dns:dnsInfor,
        token: token
    })
    res.send(dnsInfor)
})

app.post('/url_analyze/fierce', async (req,res)=>{
    let {url,token} = req.body

    let dnsInfor = await getDnsFierce(url)

    await database['fierce'].add({
        url:url,
        dns:dnsInfor,
        token: token
    })
    res.send({"fierce":dnsInfor})
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
        console.log(err)
    }


    let keys = Object.keys(domainInfor)
    for(let key of keys){
        if(!Array.isArray(domainInfor[key])){
            domainInfor[key] = new Array(domainInfor[key])
        }
    }

    await database['whois'].add({
        url:url,
        domains:domainInfor,
        token: token
    })
    res.send(domainInfor)
})

app.post('/url_analyze/sublist3r', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let domainInfor = await getDomainSub(url)
    try {
        domainInfor = JSON.parse(domainInfor)
    } catch (err){
        console.log(err)
    }

    await database['sublist3r'].add({
        url:url,
        domains:domainInfor,
        token: token
    })
    res.send(domainInfor)
})
/////////////////////////////////////////////////////




/////////////////////////////////////////////////////
// server information (using nmap information)
app.post('/url_analyze/server', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let serverInfor = await getServerInfor(url)

    await database['server'].add({
        url:url,
        server:serverInfor,
        token: token,
        vulns: serverInfor['vulns']
    })

    // Add vulns to Vulns Table
    await processVulnsTable(token, 'add', serverInfor['vulns']);

    res.send(serverInfor)
})
/////////////////////////////////////////////////////




////////////////////////////////////////////////////
// detect web firewall
app.post('/url_analyze/wafw00f', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let detectWaf = await getDWab(url)
    try {
        detectWaf = JSON.parse(detectWaf)
    } catch(err){
        console.log(err)
    }

    await database['wafw00f'].add({
        url:url,
        waf:detectWaf.wafs,
        token: token
    })
    res.send(detectWaf)
})

app.post('/url_analyze/wafw00f', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let detectWaf = await getDWab(url)
    try {
        detectWaf = JSON.parse(detectWaf)
    } catch(err){
        console.log(err)
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

    let wp = await wpScan(url)

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

    let nikto = await niktoScan(url)

    await database['nikto'].add({
        url:url,
        nikto:nikto,
        token: token,
        vulns: nikto['vulnerabilities']
    })

    // Add vulns to Vulns Table
    await processVulnsTable(token, 'add', nikto['vulnerabilities']);

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
                    
                    regex = new RegExp(pattern, 'g');
                    let searchResult = fieldContent.search(regex);
                    if (searchResult.length !== -1){
                        results.push(allReportsFromDatabase[index]._id);
                    }
                }
            }

            // Delete dumplicate elements in results
            results = [...new Set(results)]
            res.send(results);
        }
        
    }
});

// Delete all duplicate vulns 
function deleteDuplicateVulns(vulns) {
    let vulnArr = vulns.map( (vuln) => { return [vuln.Title, vuln] });
    let mapArr = new Map(vulnArr);
    vulns = [...mapArr.values()];
    return vulns;
}

// Process Vulns Table with load, add, or delete
async function processVulnsTable(token, action, vulns) {

    let currentTable = await database['vuln'].findOne({token: token});
    let currentVulns = currentTable ? currentTable['vulns'] : [];

    if (action === 'add') {
        currentVulns = currentVulns.concat(vulns);
        currentVulns = deleteDuplicateVulns(currentVulns);
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
        await database['vuln'].replaceDocument({_id: id}, {token: token, vulns: currentVulns});
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
    let vulns = []

    await database['wapp'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['wapp'] = result[0] ? result[0] : "";
        vulns = vulns.concat(result[0] ? result[0].vulns : []);
    })
    await database['whatweb'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['whatweb'] = result[0] ? result[0] : "";
        vulns = vulns.concat(result[0] ? result[0].vulns : []);
        
    })
    await database['webtech'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['webtech'] = result[0] ? result[0] : "";
        vulns = vulns.concat(result[0] ? result[0].vulns : []);

    })
    await database['netcraft'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['netcraft'] = result[0] ? result[0] : "";
        vulns = vulns.concat(result[0] ? result[0].vulns : []);

    })
    await database['largeio'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['largeio'] = result[0] ? result[0] : "";
        vulns = vulns.concat(result[0] ? result[0].vulns : []);

    })
    
    await database['dic'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['dic'] = result[0] ? result[0] : ""
    })
    await database['gobuster'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['gobuster'] = result[0] ? result[0] : ""
    })

    await database['whois'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['domain'] = result[0] ? result[0] : ""
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
        vulns = vulns.concat(result[0] ? result[0].vulns : []);

    })
    
    await database['wafw00f'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['wafw00f'] = result[0] ? result[0] : ""
    })

    await database['wpscan'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['wpscan'] = result[0] ? result[0] : "";
        vulns = vulns.concat(result[0] ? result[0].vulns : []);

    })
    await database['droopescan'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['droopescan'] = result[0] ? result[0] : "";
        vulns = vulns.concat(result[0] ? result[0].vulns : []);

    })
    await database['joomscan'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['joomscan'] = result[0] ? result[0] : "";
        vulns = vulns.concat(result[0] ? result[0].vulns : []);

    })
    await database['nikto'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['nikto'] = result[0] ? result[0] : ""
    })

    data['url'] = url

    let time = new Date()
    data['time_create'] =  time

    data['token'] = token;

    await database['report'].add(data)

    res.send("create database success")
})

app.get('/create_file', async (req,res)=>{
    let {time} = req.params
    let reportJson = await database['report'].findOne({time_create:time})

    let createStatus = await createFile(reportJson)
    if(createStatus){
        res.sendFile("/report.html")
    } else {
        res.send("Error")
    }
})

app.listen(3000, () => {
    console.log("Server is running on port 3000")
})

