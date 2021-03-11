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

module.exports = createReport
module.exports.search = search