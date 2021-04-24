'use strict'
const mongoose = require("mongoose")
const {hostDatabase,portDatabase} = require("./lib")
const { Schema } = mongoose


class databaseHandle{
    constructor(table,schema=undefined) {
        this.schemaDefault = {
            'link':{
                token: String,
                url:String,
                links:Array,
            },
            'dic':{
                token: String,
                url:String,
                dic:String
            },
            'wapp':{
                token: String,
                url:String,
                technologies: Array
            },
            'whatweb':{
                token: String,
                url:String, 
                technologies: Array
            },
            'webtech':{
                token: String,
                url:String, 
                technologies: Array
            },
            'whois':{
                token: String,
                url:String,
                domains:Array
            },
            'sublist3r':{
                token: String,
                url:String,
                domains:Array
            },
            'gobuster':{
                token: String,
                url:String,
                gobuster:Array
            },
            'dns':{
                token: String,
                url:String,
                dns:Array
            },
            'server':{
                token: String,
                url:String,
                server:Array
            },
            'netcraft':{
                token: String,
                url:String,
                technologies:Array
            },
            'largeio':{
                token: String,
                url:String,
                technologies:Array
            },
            'wafw00f':{
                token: String,
                url:String,
                waf:Array
            },
            'wpscan':{
                token: String,
                url:String,
                wp:Array
            },
            'droopescan':{
                token: String,
                url:String,
                droop:Array
            },
            'nikto':{
                token: String,
                url:String,
                nikto:Array
            },
            'report':{
                url:String,
                domain:String,
                dic:String,
                dns:String,
                gobuster:String,
                server:String,
                netcraft:String,
                largeio:String,
                wapp:String
            }
        }
        this.mapSchema = {}
        
        this.table = table
        this.schema = schema
            // initialize and connect to database
        try {
            if (this.table == undefined) {
                throw "[*] table is undefined here"
            }
            if(this.schemaDefault[this.table]){
                this.schema = this.schemaDefault[this.table]
            }
            if(this.schemaDefault[this.table] == undefined && this.schema == undefined){
                throw "[*] schema is undefined"
            }
            this.connect()
            this.createSchema()
            this.createModel()
        } catch (error) {
            console.log(error)
        }
    }
    connect() {
        // connect to database
        this.db = mongoose.connect(`mongodb://${hostDatabase}:${portDatabase}/wappalyzer`, {auto_reconnect: true, poolSize: 5, useNewUrlParser: true, useUnifiedTopology: true }).catch(error=>{
            console.log(error)
        })
        //console.log("[*] connection successfully")
    }
    disconnect() {
        mongoose.connection.close(()=>{
            console.log("[*] close")
        })
    }
    createSchema(){
        try{
            this.mapSchema[this.table] = new Schema(this.schema)
        } catch(error){
            console.log("Error:",error)
        }
    }
    createModel() {
        // create model of the table
        try {
            this.modelTable = mongoose.model(this.table, this.mapSchema[this.table])
        } catch (error) {
            console.log(error)
        }
    }
    checkExist(target) {
        return this.findOne(target)
    }
    async add(obj){
        let result = new this.modelTable(obj)
        await result.save(err=>{
            if (err) {
                console.log(err)
                return
            }
        })
    }
    async findOne(target) {
        return await (this.modelTable.findOne(target)).exec()
    }
    async getTable(token){
        return await this.modelTable.find({ token: token }).exec()
    }
    async delete(target) {
        // delete one function
        await this.modelTable.deleteOne(target, (err)=>{
            if (err) {
                console.log(err)
                return
            }
            console.log("[*] delete successfully")
        })
    }
}

module.exports = databaseHandle