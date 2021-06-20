// chịu trách nhiệm phân tích tất cả các route trên
'use strict'
//const cli = require('./cli')
const startWep = require('./cli')
const express = require('express')
const bodyParser = require('body-parser')
const databaseHandle = require('./database')
const {
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
    deleteDuplicate,
    processVulnsTable,
    fiveMostCommonElements,
    fiveMostCommonObjects,
    initializeSearch,
    updateSearchTable,
    filterDataTool,
    filterDataWapp,
    searchInReportTable,
    searchInSearchTable,
    initializeReport,
    updateReport,
    takeScreenshot,
    calRunTime
} = require('./lib')
const netcraft = require("./tools/netcrafts/netcraft")
const largeio = require("./tools/largeio/largeio")

// Add uuidv
const uuidv4 = require('uuid')

const database = {'wapp':null,'link':null}
database['link'] = new databaseHandle('link')
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

app.use((req, res, next) => {
    try {
        const checkUrl = new URL(req.query.url ? req.query.url : decodeURIComponent(req.body.url));
        res.locals.decodeUrl = decodeURIComponent(req.body.url);
    } catch {
        const replaceUrl = 'http://unvalid-url';
        req.body.url = replaceUrl;
        req.query.url = replaceUrl;
        res.locals.decodeUrl = replaceUrl;
    }
    next();
})

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

    let result = await database['report'].findOne({token:token})
    res.send(result[tool])
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
    url = decodeURIComponent(url)

    let token = req.body.token;
    
    const time_begin = new Date();
    // Wait for analyze successfully    
    let report = await startWep(database,url, token)
    const time_end = new Date();
    report['runtime'] = calRunTime(time_end, time_begin);

    // Update search table
    const searchResult = await filterDataWapp(report);
    await updateSearchTable(database, searchResult);

    // Update vulns to report table
    await processVulnsTable(database, token, 'add', report['vulns']);

    // Update wapp to report table
    await updateReport(database, token, 'wapp', report);

    res.send(report)
})

app.post('/url_analyze/netcraft', async (req,res)=>{
    let {url} = req.body

    // Get token from request
    let token = req.body.token;

    const time_begin = new Date();
    let dataRecv = await netcraft.netcraft(url)
    const time_end = new Date();

    try {
        dataRecv = JSON.parse(dataRecv)
        dataRecv['token'] = token;
    } catch (err){
        console.error(err)
    }

    let dataSend = {
        url: res.locals.decodeUrl,
        technologies:dataRecv.technologies,
        runtime: calRunTime(time_end, time_begin)
    }

    dataSend['token'] = token;
    dataSend['vulns'] = await getVulnsForNetcraft(dataRecv);

    // Update search table
    const searchResult = await filterDataTool(dataRecv);
    await updateSearchTable(database, searchResult);

    // Update vulns to report table
    await processVulnsTable(database, token, 'add', dataSend['vulns']);

    // Update netcraft to report table
    await updateReport(database, token, 'netcraft', dataSend);

    res.send(dataSend)
})

app.post('/url_analyze/largeio', async (req,res)=>{
    let {url, options} = req.body

    // Get token from request
    let token = req.body.token;
    const time_begin = new Date();
    let dataRecv = await largeio.largeio(url)
    const time_end = new Date();

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

    let dataSend = {
        url: res.locals.decodeUrl,
        technologies:tech,
        runtime: calRunTime(time_end, time_begin)
    }

    dataSend['token'] = token
    dataSend['vulns'] = await getVulnsFromExploitDB(dataRecv);

    // Update search table
    const searchResult = await filterDataTool(dataSend);
    await updateSearchTable(database, searchResult);

    // Update vulns to report table
    await processVulnsTable(database, token, 'add', dataSend['vulns']);
    
    // Update largeio to report table
    await updateReport(database, token, 'largeio', dataSend);

    res.send(dataSend)
})

app.post('/url_analyze/whatweb', async (req,res)=>{
    let {url, options} = req.body

    let token = req.body.token;

    const time_begin = new Date();
    let dataRecv = await getTechWhatWeb(url,token)
    const time_end = new Date();

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

    let dataSend = {
        url: res.locals.decodeUrl,
        technologies:tech,
        runtime: calRunTime(time_end, time_begin)
    }

    dataSend['token'] = token
    dataSend['vulns'] = dataRecv?.vulns || [];

    // Update search table
    const searchResult = await filterDataTool(dataSend);
    await updateSearchTable(database, searchResult);

    // Update vulns to report table
    await processVulnsTable(database, token, 'add', dataSend['vulns']);

    // Update whatweb to report table
    await updateReport(database, token, 'whatweb', dataSend);

    res.send(dataSend)
})

app.post('/url_analyze/webtech', async (req,res)=>{
    let {url, options} = req.body

    let token = req.body.token;

    const time_begin = new Date();
    let dataRecv = await getTechWebTech(url)
    const time_end = new Date();

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

    let dataSend = {
        url: res.locals.decodeUrl,
        technologies:tech,
        runtime: calRunTime(time_end, time_begin)
    }
    
    dataSend['token'] = token
    dataSend['vulns'] = dataRecv?.vulns || [];

    // Update search table
    const searchResult = await filterDataTool(dataSend);
    await updateSearchTable(database, searchResult);

    // Update vulns to report table
    await processVulnsTable(database, token, 'add', dataSend['vulns']);

    // Update webtech to report table
    await updateReport(database, token, 'webtech', dataSend);

    res.send(dataSend)
})
////////////////////////////////////////////////////




////////////////////////////////////////////////////
// analyze directory and file enumeration
app.post('/url_analyze/dic',async (req,res)=>{
    let {url} = req.body
    url = decodeURIComponent(url)
    
    let token = req.body.token;

    // get link from database

    let result = await database['link'].findOne({token:token})

    let arr = []
    let hostname = url.split("//")[1]
    hostname = hostname.split("/")[0]



    if(result){
        if(Array.isArray(result.links)){
            result.links.forEach(ele =>{
                if(hostname == ele.hostname){
                    arr.push(ele.pathname)
                }
            })
        }
    }


    // save to database
    let tree = createTree(arr)
    delete Object.assign(tree, {["/"]: tree[""] })[""];

    let dataSave = {
        url: res.locals.decodeUrl,
        token: token,
        trees:JSON.stringify(tree)
    }

    // Update dic to report table
    await database['report'].updateDocument({token: token}, {dic: dataSave});

    res.send(dataSave);
})

app.post('/url_analyze/gobuster', async (req,res)=>{
    let {url} = req.body

    let token = req.body.token;

    const time_begin = new Date();
    let dataRecv = await getDicGobuster(url)
    const time_end = new Date();

    if (dataRecv == "Wrong URL"){
        dataRecv = {}
    }
    try {
        dataRecv = JSON.parse(dataRecv)
    } catch (err){
        console.error(err)
    }

    let dataSend = {
        url: res.locals.decodeUrl,
        gobuster:dataRecv,
        runtime: calRunTime(time_begin, time_end),
        token: token
    }
    // Update gobuster to report table
    await database['report'].updateDocument({token: token}, {gobuster: dataSend});

    res.send(dataSend)
})
///////////////////////////////////////////////////




///////////////////////////////////////////////////
// analyze dns information 
app.post('/url_analyze/dig',async (req,res)=>{
    let {url,token} = req.body

    const time_begin = new Date();
    let dnsInfor = await getDnsDig(url)
    const time_end = new Date();

    let dataSend 
    try {
        dataSend = {
            url: res.locals.decodeUrl,
            dns:dnsInfor,
            runtime: calRunTime(time_end, time_begin),
            token: token
        }
        // Update dig to report table
        await database['report'].updateDocument({token: token}, {dig: dataSend});

    } catch(err){
        console.error(err)
    }
    
    res.send(dataSend)
})

app.post('/url_analyze/fierce', async (req,res)=>{
    let {url,token} = req.body

    const time_begin = new Date();
    let dnsInfor = await getDnsFierce(url, token)
    const time_end = new Date();

    let dataSend = {
        url: res.locals.decodeUrl,
        dns:dnsInfor,
        runtime: calRunTime(time_end, time_begin),
        token: token
    }
    // Update fierce to report table
    await database['report'].updateDocument({token: token}, {fierce: dataSend});

    res.send(dataSend)
})
///////////////////////////////////////////////////




///////////////////////////////////////////////////
// analyze information for domain
app.post('/url_analyze/whois', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    const time_begin = new Date();
    let domainInfor = await getDomainWhoIs(url)
    const time_end = new Date();

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

    let dataSend = {
        url: res.locals.decodeUrl,
        domains:domainInfor,
        runtime: calRunTime(time_end, time_begin),
        token: token
    }
    // Update whois to report table
    await database['report'].updateDocument({token: token}, {whois: dataSend});

    res.send(dataSend)
})

app.post('/url_analyze/sublist3r', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    const time_begin = new Date();
    let domainInfor = await getDomainSub(url)
    const time_end = new Date();

    try {
        domainInfor = JSON.parse(domainInfor)
    } catch (err){
        console.error(err)
    }

    let dataSend = {
        url: res.locals.decodeUrl,
        domains:domainInfor.subdomains,
        runtime: calRunTime(time_end, time_begin),
        token: token
    }
    // Update sublist3r to report table
    await database['report'].updateDocument({token: token}, {sublist3r: dataSend});

    res.send(dataSend)
})
/////////////////////////////////////////////////////




/////////////////////////////////////////////////////
// server information (using nmap information)
app.post('/url_analyze/server', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    const time_begin = new Date();
    let serverInfor = await getServerInfor(url, token)
    const time_end = new Date();

    try{
        serverInfor = JSON.parse(serverInfor);
    } catch(error) {
        console.log(error);
    }

    let dataSend = {
        url: res.locals.decodeUrl,
        server:serverInfor['nmap'],
        runtime: calRunTime(time_end, time_begin),
        token: token,
        vulns: serverInfor?.vulns || []
    }

    // Update vulns to report table
    await processVulnsTable(database, token, 'add', serverInfor['vulns']);

    // Update server to report table
    await database['report'].updateDocument({token: token}, {server: dataSend});

    res.send(serverInfor)
})
/////////////////////////////////////////////////////




////////////////////////////////////////////////////
// Detect web firewall
app.post('/url_analyze/wafw00f', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    const time_begin = new Date();
    let detectWaf = await getDWab(url,token)
    const time_end = new Date();

    try {
        detectWaf = JSON.parse(detectWaf)
    } catch(err){
        console.error(err)
    }

    let dataSend = {
        url: res.locals.decodeUrl,
        waf:detectWaf.wafs,
        runtime: calRunTime(time_end, time_begin),
        token: token
    };
    // Update wafw00f to report table
    await database['report'].updateDocument({token: token}, {wafw00f: dataSend});

    res.send(detectWaf)
})
///////////////////////////////////////////////////





////////////////////////////////////////////////////
// scanning
app.post('/url_analyze/wpscan', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    const time_begin = new Date();
    let wp = await wpScan(url, token)
    const time_end = new Date();

    let dataSend = {
        url: res.locals.decodeUrl,
        wp:wp,
        runtime: calRunTime(time_end, time_begin),
        token: token,
        vulns: wp?.vulns || []
    }

    // Update vulns to report table
    await processVulnsTable(database, token, 'add', wp['vulns']);

    // Update wpscan to report table
    await database['report'].updateDocument({token: token}, {wpscan: dataSend});

    res.send(wp)
})

app.post('/url_analyze/droopescan', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    const time_begin = new Date();
    let droope = await droopScan(url)
    const time_end = new Date();

    let dataSend = {
        url: res.locals.decodeUrl,
        droope:droope,
        runtime: calRunTime(time_end, time_begin),
        token: token,
        vulns: droope?.vulns || []
    };


    // Update vulns to report table
    await processVulnsTable(database, token, 'add', droope['vulns']);
    
    // Update droopescan to report table
    await database['report'].updateDocument({token: token}, {droopescan: dataSend});

    res.send(droope)


})

app.post('/url_analyze/joomscan', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    const time_begin = new Date();
    let joomscan = await joomScan(url)
    const time_end = new Date();

    let dataSend = {
        url: res.locals.decodeUrl,
        joomscan:joomscan,
        runtime: calRunTime(time_begin, time_end),
        token: token,
        vulns: joomscan?.vulns || []
    }

    // Update vulns to report table
    await processVulnsTable(database, token, 'add', joomscan['vulns']);

    // Update joomscan to report table
    await database['report'].updateDocument({token: token}, {joomscan: dataSend});

    res.send(joomscan)
})

app.post('/url_analyze/nikto', async (req,res)=>{
    let {url} =  req.body
    let token = req.body.token;

    const time_begin = new Date();
    let nikto = await niktoScan(url, token)
    const time_end = new Date();

    let dataSend = {
        url: res.locals.decodeUrl,
        nikto:nikto,
        runtime: calRunTime(time_end, time_begin),
        token: token,
        vulns: nikto?.vulnerabilities || []
    }
    // Update nikto to report table
    await database['report'].updateDocument({token: token}, {nikto: dataSend});
    
    res.send(dataSend)
})
///////////////////////////////////////////////////

app.get('/analyze_result/screenshot', async (req,res)=>{
    let {url,pic,token} = req.query
    url = decodeURIComponent(url)
    if (pic){
        res.sendFile(__dirname + '/images/' + pic);
        return
    }
    
    let picName = await takeScreenshot(url, token);
    await database['report'].updateDocument({token: token}, {pic: token + '.png' });
    res.sendFile(__dirname + picName);

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
    
    let vulnTable = await database['report'].findOne({token: token});

    res.send({vulns: vulnTable.vulns});
});

app.get('/dashboard/num_report', async (req,res)=>{
    let listReport = await database['report'].getTable({})
    res.send(listReport.length.toString())
})

app.get('/dashboard/element', async (req, res) => {
    const {type, option} = req.query;
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
    
    if (option === 'number') {
        res.send([...new Set(elementsList)].length.toString());
    } else {
        res.send(fiveMostCommonElements(elementsList, keyInResult, 5));
    }
})

app.get('/dashboard/num_vuln', async (req, res) => {
    let arrayOfReports = await database['report'].getTable({});

    let arrayOfVulns = arrayOfReports.reduce((result, report) => {
        return result.concat(report.vulns);
    }, []);

    arrayOfVulns = deleteDuplicate('Title', arrayOfVulns);
    
    res.send(arrayOfVulns.length.toString());
});

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

            res.send(fiveMostCommonElements(arrayOfUrls, 'url', 5));
        }
        // If type is vuln
        if (type === 'vuln') {
           let arrayOfVulns = arrayOfReports.reduce((resultAllReports, report) => {
                return resultAllReports.concat(report.vulns);
            }, []);

            res.send(fiveMostCommonObjects(arrayOfVulns, 'Title', 'vuln', 5));
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

            res.send(fiveMostCommonObjects(arrayOfWafs, 'firewall', 'waf', 5));
        }
    }
});

app.listen(3000, () => {
    console.log("Server is running on port 3000")
})

