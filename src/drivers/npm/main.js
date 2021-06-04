// chịu trách nhiệm phân tích tất cả các route trên
'use strict'
//const cli = require('./cli')
const fs = require('fs')
const startWep = require('./cli')
const express = require('express')
const bodyParser = require('body-parser')
const { spawnSync } = require('child_process')
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
    processVulnsTable,
    fiveMostCommonUrls,
    fiveMostCommonVulns,
    fiveMostCommonWafs,
    initializeSearch,
    updateSearchTable,
    filterDataTool,
    filterDataWapp,
    searchInReportTable,
    searchInSearchTable,
    filterFramework,
    filterLanguage,
    initializeReport,
    updateReport,
    intersectionListObject,
    intersectionList,
    countExist,
    takeScreenshot,
    getHostFromUrl
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
database['search'] = new databaseHandle('search')

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
app.get("/initialize", async (req, res) => {

    const {url} = req.query;
    let token = uuidv4();

    // Check if report with this token exist ?
    // If no initialize a new report within this token
    let reportExist = await database['report'].findOne({token: token});
    if (!reportExist) {
        let report = initializeReport(url, token);
        await database['report'].add(report);
    }

    // Check if have anyone in search table
    // If no initialize a new one
    const searchExist = await database['search'].findOne({token: token});
    if (!searchExist) {
        const target = initializeSearch(url, token);
        await database['search'].add(target);
    }

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
    let report = await startWep(database,url, token)

    // Update search table
    const searchResult = await filterDataWapp(report);
    await updateSearchTable(database, searchResult);

    //Update wapp to report table
    await updateReport(database, token, 'wapp', report);

    // data saved in database, and get it from database
    let dataSend = await database['wapp'].findOne({token:token});
    
    await processVulnsTable(database, token, 'add', dataSend['vulns']);

    res.send(dataSend)
})

app.post('/url_analyze/netcraft', async (req,res)=>{
    let {url} = req.body

    // Get token from request
    let token = req.body.token;

    let dataRecv = await netcraft.netcraft(url)
    try {
        dataRecv = JSON.parse(dataRecv)
        dataRecv['token'] = token;
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

    // Update search table
    const searchResult = await filterDataTool(dataRecv);
    await updateSearchTable(database, searchResult);

    // Add vulns to Vulns Table
    await processVulnsTable(database, token, 'add', dataSend['vulns']);

    //Update wapp to report table
    await updateReport(database, token, 'netcraft', dataSend);

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

    // Update search table
    const searchResult = await filterDataTool(dataSend);
    await updateSearchTable(database, searchResult);

    // Add vulns to Vulns Table
    await processVulnsTable(database, token, 'add', dataSend['vulns']);
    
    //Update wapp to report table
    await updateReport(database, token, 'largeio', dataSend);

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

    // Update search table
    const searchResult = await filterDataTool(dataSend);
    await updateSearchTable(database, searchResult);

    // Add vulns to Vulns Table
    await processVulnsTable(database, token, 'add', dataSend['vulns']);

    //Update wapp to report table
    await updateReport(database, token, 'whatweb', dataSend);

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

    // Update search table
    const searchResult = await filterDataTool(dataSend);
    await updateSearchTable(database, searchResult);

    // Add vulns to Vulns Table
    await processVulnsTable(database, token, 'add', dataSend['vulns']);

    //Update wapp to report table
    await updateReport(database, token, 'webtech', dataSend);

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

    let dataSave = {
        url:url,
        token: token,
        trees:JSON.stringify(tree)
    }

    await database['report'].updateDocument({token: token}, {dic: dataSave});

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

    await database['report'].updateDocument({token: token}, {gobuster: dataSend});

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

        await database['report'].updateDocument({token: token}, {dig: dataSend});

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

    await database['report'].updateDocument({token: token}, {fierce: dataSend});

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

    await database['report'].updateDocument({token: token}, {whois: dataSend});

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

    await database['report'].updateDocument({token: token}, {sublist3r: dataSend});

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

    let dataSend = await database['server'].add({
        url:url,
        server:serverInfor['nmap'],
        token: token,
        vulns: serverInfor['vulns']
    })

    // Add vulns to Vulns Table
    await processVulnsTable(database, token, 'add', serverInfor['vulns']);

    await database['report'].updateDocument({token: token}, {server: dataSend});

    res.send(serverInfor)
})
/////////////////////////////////////////////////////




////////////////////////////////////////////////////
// Detect web firewall
app.post('/url_analyze/wafw00f', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let detectWaf = await getDWab(url,token)
    try {
        detectWaf = JSON.parse(detectWaf)
    } catch(err){
        console.error(err)
    }

    let dataSend = await database['wafw00f'].add({
        url:url,
        waf:detectWaf.wafs,
        token: token
    })

    await database['report'].updateDocument({token: token}, {wafw00f: dataSend});

    res.send(detectWaf)
})
///////////////////////////////////////////////////





////////////////////////////////////////////////////
// scanning
app.post('/url_analyze/wpscan', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let wp = await wpScan(url, token)

    let dataSend = await database['wpscan'].add({
        url:url,
        wp:wp,
        token: token,
        vulns: wp['vulns']
    })

    // Add vulns to Vulns Table
    await processVulnsTable(database, token, 'add', wp['vulns']);

    await database['report'].updateDocument({token: token}, {wpscan: dataSend});

    res.send(wp)
})

app.post('/url_analyze/droopescan', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let droope = await droopScan(url)

    let dataSend = await database['droopescan'].add({
        url:url,
        droope:droope,
        token: token,
        vulns: droope['vulns']
    })


    // Add vulns to Vulns Table
    await processVulnsTable(database, token, 'add', droope['vulns']);

    await database['report'].updateDocument({token: token}, {droopescan: dataSend});

    res.send(droope)


})

app.post('/url_analyze/joomscan', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let joomscan = await joomScan(url)

    let dataSend = await database['joomscan'].add({
        url:url,
        joomscan:joomscan,
        token: token,
        vulns: joomscan['vulns']
    })

    // Add vulns to Vulns Table
    await processVulnsTable(database, token, 'add', joomscan['vulns']);

    await database['report'].updateDocument({token: token}, {joomscan: dataSend});

    res.send(joomscan)
})

app.post('/url_analyze/nikto', async (req,res)=>{
    let {url} =  req.body
    let token = req.body.token;

    let nikto = await niktoScan(url, token)

    let dataSend = await database['nikto'].add({
        url:url,
        nikto:nikto,
        token: token,
        vulns: nikto['vulnerabilities']
    })

    // Add vulns to Vulns Table
    // await processVulnsTable(token, 'add', nikto['vulnerabilities']);

    await database['report'].updateDocument({token: token}, {nikto: dataSend});
    
    res.send(nikto)
})
///////////////////////////////////////////////////

app.get('/analyze_result/screenshot', async (req,res)=>{
    let {url,pic,token} = req.query
    if (pic){
        res.sendFile(__dirname + '/images/' + pic)
        return
    }
    
    console.log("take sceenshot")
    let picName = await takeScreenshot(url)
    await database['report'].updateDocument({token: token}, {pic:picName.split('/').pop() });
    res.sendFile( __dirname + '/'+ picName);
})

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
    let {pattern, option} = req.query;

    if (!pattern) {
        res.send([]);
        
    } else {
        // Delete all begining and ending space
        pattern = pattern.trim();
        if (pattern === '') {
            res.send([]);

        } else {
            let results = [];

            // Find all spaces in pattern parameter and replace them with "|"
            let regex = new RegExp('\\s+', 'g');
            pattern = `(${pattern.replaceAll(regex, '|')})`

            // Dependent on option, we choose the suitable type of searching
            if (!option || option === 'search') {
                results =  await searchInSearchTable(database, pattern);

            } else if (option === 'report') {
                results = await searchInReportTable(database, pattern);

            } else {
                let resultsFromSearch = await searchInSearchTable(database, pattern);
                let resultsFromReport = await searchInReportTable(database, pattern);

                results = results.concat(resultsFromReport).concat(resultsFromSearch);
            }

            // Delete dumplicate elements in results
            results = deleteDuplicate('_id', results);
            res.send(results);
        }
        
    }
});

app.post('/update_vulns_table', async(req, res) => {
    let {token, action, vulns} = req.body;
    await processVulnsTable(database, token, action, vulns);
    
    let vulnTable = await database['vuln'].getTable({token: token});

    res.send(vulnTable[0]);
});

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
    let dataSend = countExist(unionList,"programing_language")
    res.send(dataSend)
})

app.get('/dashboard/framework_ratio',async (req,res)=>{
    let listReport = await database['report'].getTable({})

    let unionList = []
    for (let report of listReport){
        unionList.push(...report["framework"])
    }

    let dataSend = countExist(unionList,'framework')
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

            res.send(fiveMostCommonWafs(arrayOfWafs));
        }
    }
});

app.listen(3000, () => {
    console.log("Server is running on port 3000")
})

