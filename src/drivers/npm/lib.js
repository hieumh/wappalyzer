const request = require('async-request')

let host = "172.17.0.4"
let port = "4000"

async function createReport(data){
    let temp = data
    for(let i = 0 ; i< temp.technologies.length; i++){
        let result = await request(`http://${host}:${port}/cve?target=${data.technologies[i].name}&year=2020`)
       
        let cve = JSON.parse(result.body)
        temp.technologies[i]['cve'] = cve[0]

    }
    
    return temp
}

async function search(data){
    let result = await request(`http://${host}:${port}/cve?target=${data.target}&year=${data.year}`)
    let cve = JSON.parse(result.body)
    
    return cve[0]
}

function handleLink(str){
    if (str == undefined){
        return 0
    }

    return str.slice(1,-1).split('/')
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
        // intial object or assign value
        if (path[path_str[index]][path_str[index+1]]==undefined){
            path[path_str[index]][path_str[index+1]] = {}
        } 
    
        index += 1
        return _treeParse(path_str,index,path[path_str[index-1]]) 
    }

    return _treeParse(path_str,0,path)
}

function createTree(arr){
    let str
    let obj = {}
    for (let i of arr){
        str = handleLink(i)
        obj = treeParse(str,0,obj)
    }
    return obj
}
module.exports = createReport
module.exports.search = search
module.exports.treeParse = treeParse
module.exports.handleLink = handleLink
module.exports.createTree = createTree