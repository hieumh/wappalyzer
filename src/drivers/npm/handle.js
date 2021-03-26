// chịu trách nhiệm phân tích tất cả các route trên
'use strict'
//const cli = require('./cli')
const fs = require('fs')
const startWep = require('./cli')
const express = require('express')
const bodyParser = require('body-parser')
const dataHandle = require('./database')
const {search,createTree} = require('./lib')

const database = {'tech':null,'link':null}
database['tech'] = new dataHandle('tech')
database['link'] = new dataHandle('link')



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

app.post('/url_analyze', async (req,res) => {
    let {url, options} = await req.body
    
    // wait for analyze successfully
    await startWep(database,url)
    url = url.split("//")[1]

    // data saved in database, and get it from database
    let data
    await database['tech'].findOne({urls:url}).then((result)=>{
        data = result
    })
    res.send(JSON.stringify(data))
})

app.get('/search/:target/:year', async (req,res) => {
    const {target, year} = req.params
    let data = await search({target:target,year:year})

    res.send(JSON.stringify(data))
})

app.get('/report/:id', async (req,res)=>{
    const {id} = req.params

    const result = await database['tech'].findOne({'_id':id})
    res.send(JSON.stringify(result))
})

app.get('/report', async (req,res)=>{
    let data
    await database['tech'].getTable().then((result)=>{
        data = result
    })

    res.send(JSON.stringify(data))
})

app.get('/last_report', async (req,res)=>{
    let data
    await database['tech'].getTable().then((result)=>{
        data = result
    })
    res.send(JSON.stringify(data[data.length-1]))
})

app.get('/urls_tree', async (req,res)=>{
    const {url} = req.query

    let result
    await database['link'].findOne({url:url}).then((data)=>{
        result = data
    })
    let arr = []
    let hostname = url.split("/")[0]

    result.links.forEach(ele =>{
        if(hostname == ele.hostname){
            arr.push(ele.pathname)
        }
    })
    
    let tree = createTree(arr)

    res.send(JSON.stringify(tree))
})


app.listen(3000, () => {
    console.log("Server is running on port 3000")
})

