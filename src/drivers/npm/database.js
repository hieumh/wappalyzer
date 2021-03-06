'use strict'
const mongoose = require("mongoose")
const {hostDatabase,portDatabase} = require("./lib")
const { Schema } = mongoose


class databaseHandle{
    constructor(table,schema=undefined){
        this.schemaDefault = {
            'link':{
                token: String,
                url:String,
                links:Array,
            },
            'dic':{
                url:String,
                token: String,
                trees: Object
            },
            'wapp':{
                token: String,
                url:String,
                technologies: Array,
                vulns: Array,
                runtime: String
            },
            'whatweb':{
                token: String,
                url:String, 
                technologies: Array,
                vulns: Array,
                runtime: String
            },
            'webtech':{
                token: String,
                url:String, 
                technologies: Array,
                vulns: Array,
                runtime: String
            },
            'whois':{
                token: String,
                url:String,
                domains:Object,
                runtime: String
            },
            'sublist3r':{
                token: String,
                url:String,
                domains:Array,
                runtime: String
            },
            'gobuster':{
                token: String,
                url:String,
                gobuster:Object,
                runtime: String
            },
            'dig':{
                token: String,
                url:String,
                dns:String,
                runtime: String
            },
            'fierce':{
                token: String,
                url:String,
                dns:String,
                runtime: String
            },
            'nmap':{
                token: String,
                url:String,
                nmap:Array,
                vulns: Array,
                runtime: String
            },
            'netcraft':{
                token: String,
                url:String,
                technologies:Array,
                vulns: Array,
                runtime: String,
            },
            'largeio':{
                token: String,
                url:String,
                technologies:Array,
                vulns: Array,
            },
            'wafw00f':{
                token: String,
                url:String,
                waf:Array,
                runtime: String
            },
            'wpscan':{
                token: String,
                url:String,
                wp:Object,
                vulns: Array,
                runtime: String
            },
            'droopescan':{
                token: String,
                url:String,
                droop:Object,
                vulns: Array,
                runtime: String
            },
            'joomscan':{
                token: String,
                url:String,
                joomscan:String,
                vulns: Array,
                runtime: String
            },
            'nikto':{
                token: String,
                url:String,
                nikto:Array,
                vulns: Array,
                runtime: String
            },
            'vuln': {
                token: String,
                vulns: Array
            },
            'report':{
                url:String,
                domain:Object,
                dic:Object,
                dig:Object,
                fierce:Object,
                gobuster:Object,
                nmap:Object,
                netcraft:Object,
                largeio:Object,
                wapp:Object,
                whatweb:Object,
                webtech:Object,
                whois:Object,
                sublist3r:Object,
                wafw00f:Object,
                wpscan:Object,
                droopescan:Object,
                joomscan:Object,
                nikto:Object,
                vulns: Object,
                time_create:String,
                token: String,
                pic:String
            },
            'search' : { 
                url: Array,
                token: String,
                operatingsystems: Array,
                webservers: Array,
                webframeworks: Array,
                javascriptframeworks: Array,
                cms: Array,
                programminglanguages: Array,
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
            console.error(error)
        }
    }
    connect(){
        // connect to database
        this.db = mongoose.connect(`mongodb://${hostDatabase}:${portDatabase}/wappalyzer`, {auto_reconnect: true, poolSize: 5, useNewUrlParser: true, useUnifiedTopology: true }).catch(error=>{
            console.error(error)
        })
    }
    disconnect(){
        mongoose.connection.close(()=>{
            console.error("[*] close")
        })
    }
    createSchema(){
        try{
            this.mapSchema[this.table] = new Schema(this.schema)
        } catch(error){
            console.error("Error:",error)
        }
    }
    createModel(){
        // create model of the table
        try {
            this.modelTable = mongoose.model(this.table, this.mapSchema[this.table])
        } catch (error){
            console.error(error)
        }
    }
    checkExist(target){
        return this.findOne(target)
    }
    async add(obj){
        let currentTable = await (this.modelTable.findOne({token: obj.token})).exec();
        let _id = currentTable ? currentTable['_id'] : null;

        if (_id) {

            await this.modelTable.replaceOne({_id: _id}, obj);
            return obj;

        } else {

            let result = new this.modelTable(obj)
            try{
                let check = await result.save()
                return check
            } catch(err){
                console.error(err.stack)
            }

        }
        
    }
    async findOne(target){
        return await (this.modelTable.findOne(target)).exec()
    }
    async getTable(condition, exclusion){
        // to get all row in table condition={}, exclusion={_id}
        return await this.modelTable.find(condition, exclusion).exec()
    }
    async replaceDocument(condition, replaceObj) {
        await this.modelTable.replaceOne(condition, replaceObj);
    }

    async updateDocument(condition, fieldForUpdate) {
        await this.modelTable.updateOne(condition, fieldForUpdate);
    }

    async elementMatch(field, condition) {
        return await this.modelTable.find({}).elemMatch(field, condition);
    }

    async delete(target){
        // delete one function
        await this.modelTable.deleteOne(target, (err)=>{
            if (err) {
                console.error(err)
                return
            }
        })
    }
}

module.exports = databaseHandle