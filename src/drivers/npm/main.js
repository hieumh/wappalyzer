// chịu trách nhiệm phân tích tất cả các route trên
'use strict'
//const cli = require('./cli')
const fs = require('fs')
const startWep = require('./cli')
const express = require('express')
const bodyParser = require('body-parser')
const databaseHandle = require('./database')
const addCve = require('./lib')
const {search,createTree,getDns,getDomainSub,getDomainWhoIs,getServerInfor,getDicGobuster,getTechWhatWeb,getTechWebTech,getDWab,wpScan,droopScan,joomScan,niktoScan,searchSploit} = require('./lib')
const netcraft = require("./tools/netcrafts/netcraft")
const largeio = require("./tools/largeio/largeio")

// Add uuidv
const uuidv4 = require('uuid')

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

database['dns'] = new databaseHandle('dns')
database['server'] = new databaseHandle('server')

database['wafw00f'] = new databaseHandle('wafw00f')

database['wpscan'] = new databaseHandle('wpscan')
database['droopescan'] = new databaseHandle('droopescan')
database['joomscan'] = new databaseHandle('joomscan')
database['nikto'] = new databaseHandle('nikto')

database['report'] = new databaseHandle('report')




const app = express()
app.use(bodyParser.json({limit:'50mb'}))
app.use(bodyParser.urlencoded({
    extended:false,
    limit:"50mb"
}))

app.use((req,res,next) =>{
    res.append('Access-Control-Allow-Origin',["http://localhost:3001"])
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
    let {url} = req.query

    let result 
    await database[tool].findOne({url:url}).then(data =>{
        result = data
    })
    res.send(JSON.stringify(result))
})

///////////////////////////////////////////////////////////////
// analyze technologies for url
app.post('/url_analyze/wapp',async (req,res) => {
    let {url} = req.body

    let token = req.body.token;

    // wait for analyze successfully
    await startWep(database,url, token)

    // data saved in database, and get it from database
    let data = await database['wapp'].findOne({url:url})

    // log here
    // res.send(JSON.stringify(data))
    res.send(data)
})

app.post('/url_analyze/netcraft', async (req,res)=>{
    let {url} = req.body

    // Get token from request
    let token = req.body.token;

    let result 
    await netcraft.netcraft(url).then(data=>{
        result = JSON.parse(data)
    })

    let temp
    await addCve({
        url:url,
        technologies:result.technologies
    }).then(data=>{
        temp = data
    })

    // Add token to result
    temp['token'] = token
    
    await database['netcraft'].add(temp)
    res.send(JSON.stringify(temp))
})

app.post('/url_analyze/largeio', async (req,res)=>{
    let {url, options} = req.body

    // Get token from request
    let token = req.body.token;

    let result 
    await largeio.largeio(url).then(data=>{
        result = JSON.parse(data)
    })

    let temp 
    let tech
    if(JSON.stringify(result.technologies) === "[]"){
        tech = []
    } else {
        tech = result.technologies
    }

    await addCve({
        url:url,
        technologies:tech
    }).then(data=>{
        temp =data
    })
    
    // Add token to result
    temp['token'] = token
    
    await database['largeio'].add(temp)
    res.send(JSON.stringify(temp))
})

app.post('/url_analyze/whatweb', async (req,res)=>{
    let {url, options} = req.body

    let token = req.body.token;

    let result 
    await getTechWhatWeb(url).then(data=>{
        result = JSON.parse(data)
    })

    let tech
    if(JSON.stringify(result.technologies) === "[]"){
        tech = []
    } else {
        tech = result.technologies
    }

    let temp
    await addCve({
        url:url,
        technologies:tech
    }).then(data=>{
        temp =data
    })
    
    temp['token'] = token
    
    await database['whatweb'].add(temp)
    res.send(JSON.stringify(temp))
})

app.post('/url_analyze/webtech', async (req,res)=>{
    let {url, options} = req.body

    let token = req.body.token;

    let result 
    await getTechWebTech(url).then(data=>{
        result = JSON.parse(data)
    })

    let tech
    if(JSON.stringify(result.technologies) === "[]"){
        tech = []
    } else {
        tech = result.technologies
    }

    let temp
    await addCve({
        url:url,
        technologies:tech
    }).then(data=>{
        temp =data
    })
    
    temp['token'] = token

    await database['webtech'].add(temp)
    res.send(JSON.stringify(temp))
})
////////////////////////////////////////////////////




////////////////////////////////////////////////////
// analyze directory and file enumeration
app.post('/url_analyze/dic',async (req,res)=>{
    let {url} = req.body

    let token = req.body.token;

    // get link from database
    let result
    await database['link'].findOne({url:url}).then((data)=>{
        result = data
    })

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
    await database['dic'].add({
        url:url,
        dic:JSON.stringify(tree),
        token: token
    })

    res.send(JSON.stringify(tree))
})


app.post('/url_analyze/gobuster', async (req,res)=>{
    let {url} = req.body

    let token = req.body.token;

    let temp
        await getDicGobuster(url).then(data=>{
            if (data == "Wrong URL"){
                temp = {}
            } else {
                temp = JSON.parse(data)
            }
        })

    // add to database
    let data = {
        url:url,
        gobuster:temp,
        token: token
    }
    await database['gobuster'].add(data)
    res.send(JSON.stringify(data))
})
///////////////////////////////////////////////////




///////////////////////////////////////////////////
// analyze dns information 
app.post('/url_analyze/dns',async (req,res)=>{
    let {url} = req.body
    
    let token = req.body.token;

    let dnsInfor 
    await getDns(url).then(data=>{
        dnsInfor= JSON.parse(data)
    })


    await database['dns'].add({
        url:url,
        dns:dnsInfor,
        token: token
    })
    res.send(JSON.stringify(dnsInfor))
})
///////////////////////////////////////////////////




///////////////////////////////////////////////////
// analyze information for domain
app.post('/url_analyze/whois', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let domainInfor 
    await getDomainWhoIs(url).then(data=>{
        domainInfor = JSON.parse(data)
    })

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
    res.send(JSON.stringify(domainInfor))
})

app.post('/url_analyze/sublist3r', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let domainInfor 
    await getDomainSub(url).then(data=>{
        domainInfor = JSON.parse(data)
    })

    await database['sublist3r'].add({
        url:url,
        domains:domainInfor,
        token: token
    })
    res.send(JSON.stringify(domainInfor))
})
/////////////////////////////////////////////////////




/////////////////////////////////////////////////////
// server information (using nmap information)
app.post('/url_analyze/server', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let serverInfor 
    await getServerInfor(url).then(data=>{
        serverInfor=data
    })

    // console.log(`this is server infor ${serverInfor}`)
    await database['server'].add({
        url:url,
        server:serverInfor,
        token: token
    })
    res.send(JSON.stringify(serverInfor))
})
/////////////////////////////////////////////////////




////////////////////////////////////////////////////
// detect web firewall
app.post('/url_analyze/wafw00f', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let detectWaf 
    await getDWab(url).then(data=>{
        detectWaf=data
    })

    // console.log(`this is server infor ${serverInfor}`)
    await database['wafw00f'].add({
        url:url,
        waf:detectWaf,
        token: token
    })
    res.send(JSON.stringify(detectWaf))
})
///////////////////////////////////////////////////





////////////////////////////////////////////////////
// scanning
app.post('/url_analyze/wpscan', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let wp 
    await wpScan(url).then(data=>{
        wp=data
    })

    // console.log(`this is server infor ${serverInfor}`)
    await database['wpscan'].add({
        url:url,
        wp:wp,
        token: token
    })
    res.send(JSON.stringify(wp))
})

app.post('/url_analyze/droopescan', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;

    let droop 
    await droopScan(url).then(data=>{
        droop=data
    })

    // console.log(`this is server infor ${serverInfor}`)
    await database['droopescan'].add({
        url:url,
        droop:droop,
        token: token
    })
    res.send(JSON.stringify(droop))
})

app.post('/url_analyze/joomscan', async (req,res)=>{
    let {url} =  req.body

    let token = req.body.token;
    console.log("joomscan here")

    let joomscan 
    await joomScan(url).then(data=>{
        joomscan=data
    })

    // console.log(`this is server infor ${serverInfor}`)
    await database['joomscan'].add({
        url:url,
        joomscan:joomscan,
        token: token
    })
    res.send(JSON.stringify(joomscan))
})

app.post('/url_analyze/nikto', async (req,res)=>{
    let {url} =  req.body
    let token = req.body.token;
    let nikto = await niktoScan(url)

    // console.log(`this is server infor ${serverInfor}`)
    await database['nikto'].add({
        url:url,
        nikto:nikto,
        token: token
    })
    res.send(nikto)
})
///////////////////////////////////////////////////





//////////////////////////////////////////////////////////////////
app.get('/search/:target/:year', async (req,res)=>{
    const {target, year} = req.params
    let data = await search({target:target,year:year})

    res.send(JSON.stringify(data))
})

app.get('/searchDatabase', async (req, res) => {
    let fields = ['url', 'domain', 'dic','dns','gobuster','server','netcraft','largeio','wapp'];

    // Pre-process pattern
    let pattern = req.query.pattern;

    // Find all spaces and replace them with "|"
    let regex = new RegExp('\\s', 'g');
    pattern = `(${pattern.replaceAll(regex, '|')})`;

    let results = [];

    for (let index = 0; index < fields.length; index++) {
        try {
            regex = new RegExp(pattern, 'g');
            let resultsFromDatabase = await database['report'].getTable({ [fields[index]]: regex });
            
            // If results from database are non-empty
            // Get all _id of all reports
            for (let position = 0; position < resultsFromDatabase.length; position++){
                results.push(String(resultsFromDatabase[position]._id));
            }

        } catch (err) {
            console.log(err);
        }
    }
    // Delete dumplicate elements in results
    results = [...new Set(results)];

    res.send(JSON.stringify(results));
});

// create report (base on the last result of each table)
app.post("/create_report",async (req,res)=>{
    let data = {}
    let {url} = req.body

    let token = req.body.token;
    
    await database['dic'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['dic'] = JSON.stringify(result)
    })

    await database['wapp'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['wapp'] = JSON.stringify(result)
    })
    await database['whois'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['domain'] = JSON.stringify(result)
    })
    await database['dns'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['dns'] = JSON.stringify(result)
    })
    await database['server'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['server'] = JSON.stringify(result)
    })
    await database['netcraft'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['netcraft'] = JSON.stringify(result)
    })
    await database['largeio'].getTable({token: token},{_id: 0, token: 0}).then((result)=>{
        data['largeio'] = JSON.stringify(result)
    })
    data['url'] = url
    await database['report'].add(data)

    res.send("create database success")
})

// get specified report
app.get('/report/:id', async (req,res)=>{
    const {id} = req.params

    const result = await database['report'].findOne({'_id':id})
    res.send(JSON.stringify(result))
})

// get all report
app.get('/report', async (req,res)=>{
    let data
    await database['report'].getTable().then((result)=>{
        data = result
    })

    res.send(JSON.stringify(data))
})

// get last report
app.get('/last_report', async (req,res)=>{
    let data
    await database['wapp'].getTable().then((result)=>{
        data = result
    })
    res.send(JSON.stringify(data[data.length-1]))
})


app.listen(3000, () => {
    console.log("Server is running on port 3000")
})

