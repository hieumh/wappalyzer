'use strict'
const mongoose = require("mongoose")
const {hostDatabase,portDatabase} = require("./lib")
const { Schema } = mongoose


class databaseHandle{
    constructor(table,schema=undefined) {
        this.schemaDefault = {
            'link':{
                url:String,
                links:Array,
            },
            'dic':{
                url:String,
                dic:String
            },
            'wapp':{
                url:String,
                technologies: Array
            },
            'whatweb':{
                url:String, 
                technologies: Array
            },
            'webtech':{
                url:String, 
                technologies: Array
            },
            'whois':{
                url:String,
                domains:Array
            },
            'sublist3r':{
                url:String,
                domains:Array
            },
            'gobuster':{
                url:String,
                gobuster:Array
            },
            'dns':{
                url:String,
                dns:Array
            },
            'server':{
                url:String,
                server:Array
            },
            'netcraft':{
                url:String,
                technologies:Array
            },
            'largeio':{
                url:String,
                technologies:Array
            },
            'wafw00f':{
                url:String,
                waf:Array
            },
            'wpscan':{
                url:String,
                wp:Array
            },
            'droopescan':{
                url:String,
                droop:Array
            },
            'nikto':{
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
    async getTable(){
        return await this.modelTable.find({}).exec()
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