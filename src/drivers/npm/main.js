// chịu trách nhiệm phân tích tất cả các route trên
'use strict'
//const cli = require('./cli')
const fs = require('fs')
const startWep = require('./cli')
const express = require('express')
const bodyParser = require('body-parser')
const dataHandle = require('./database')
const addCve = require('./lib')
const {search,createTree,getDns,getDomain,getServerInfor} = require('./lib')
const netcraft = require("./tools/netcrafts/netcraft")
const largeio = require("./tools/largeio/largeio")

const database = {'wapp':null,'link':null}
database['wapp'] = new dataHandle('wapp')
database['link'] = new dataHandle('link')
database['domain'] = new dataHandle('domain')
database['dns'] = new dataHandle('dns')
database['server'] = new dataHandle('server')
database['netcraft'] = new dataHandle('netcraft')
database['largeio'] = new dataHandle('largeio')
database['dic'] = new dataHandle('dic')
database['report'] = new dataHandle('report')




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

// analyze url with specified tools
app.post('/url_analyze/wapp',async (req,res) => {
    let {url} = req.body
    
    // wait for analyze successfully
    await startWep(database,url)

    // data saved in database, and get it from database
    let data
    await database['wapp'].findOne({url:url}).then((result)=>{
        data = result
    })
    res.send(JSON.stringify(data))
})

app.post('/url_analyze/dic',async (req,res)=>{
    let {url} = req.body

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
        dic:JSON.stringify(tree)
    })

    res.send(JSON.stringify(tree))
})

app.post('/url_analyze/dns',async (req,res)=>{
    let {url} = req.body
    let dnsInfor 
    await getDns(url).then(data => {
        dnsInfor= JSON.parse(data)
    })

    await database['dns'].add({
        url:url,
        dns:dnsInfor
    })
    res.send(JSON.stringify(dnsInfor))
})

app.post('/url_analyze/domain', async (req,res)=>{
    let {url} =  req.body
    let domainInfor 
    await getDomain(url).then(data =>{
        domainInfor = JSON.parse(data)
    })

    await database['domain'].add({
        url:url,
        domains:domainInfor
    })
    res.send(JSON.stringify(domainInfor))
})

app.post('/url_analyze/server', async (req,res)=>{
    let {url} =  req.body
    let serverInfor 
    await getServerInfor(url).then(data =>{
        serverInfor=data
    })

    // console.log(`this is server infor ${serverInfor}`)
    await database['server'].add({
        url:url,
        server:serverInfor
    })
    res.send(JSON.stringify(serverInfor))
})

app.post('/url_analyze/netcraft', async (req,res)=>{
    let {url} = req.body

    let result 
    await netcraft.netcraft(url).then(data => {
        result = JSON.parse(data)
    })

    let temp 
    await addCve({
        url:url,
        technologies:result.technologies
    }).then(data=>{
        temp =data
    })
    
    await database['netcraft'].add(temp)
    res.send(JSON.stringify(temp))
})

app.post('/url_analyze/largeio', async (req,res)=>{
    let {url, options} = req.body

    let result 
    await largeio.largeio(url).then(data => {
        result = JSON.parse(data)
    })

    let temp 
    let tech
    if(!result.technologies){
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
    
    
    await database['largeio'].add(temp)
    res.send(JSON.stringify(temp))
})

//////////////////////////////////////////////////////////////////
app.get('/search/:target/:year', async (req,res) => {
    const {target, year} = req.params
    let data = await search({target:target,year:year})

    res.send(JSON.stringify(data))
})

app.get("/url_analyze/:tool",async (req,res)=>{
    const {tool} = req.params
    const url = req.query.url

    const result = await database[tool].findOne({url:url})
})

// create report (base on the last result of each table)
app.post("/create_report",async (req,res)=>{
    let data = {}
    let {url} = req.body
    await database['dic'].getTable().then((result)=>{
        data['dic'] = result
    })

    await database['wapp'].getTable().then((result)=>{
        data['wapp'] = result
    })
    await database['domain'].getTable().then((result)=>{
        data['domain'] = result
    })
    await database['dns'].getTable().then((result)=>{
        data['dns'] = result
    })
    await database['server'].getTable().then((result)=>{
        data['server'] = result
    })
    await database['netcraft'].getTable().then((result)=>{
        data['netcraft'] = result
    })
    await database['largeio'].getTable().then((result)=>{
        data['largeio'] = result
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

