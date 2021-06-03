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
                programing_language:Array,
                framework:Array,
            },
            'whatweb':{
                token: String,
                url:String, 
                technologies: Array,
                vulns: Array,
                programing_language:Array,
                framework:Array,
            },
            'webtech':{
                token: String,
                url:String, 
                technologies: Array,
                vulns: Array,
                programing_language:Array,
                framework:Array,
            },
            'whois':{
                token: String,
                url:String,
                domains:Object
            },
            'sublist3r':{
                token: String,
                url:String,
                domains:Array
            },
            'gobuster':{
                token: String,
                url:String,
                gobuster:Object
            },
            'dig':{
                token: String,
                url:String,
                dns:String
            },
            'fierce':{
                token: String,
                url:String,
                dns:String
            },
            'server':{
                token: String,
                url:String,
                server:Array,
                vulns: Array
            },
            'netcraft':{
                token: String,
                url:String,
                technologies:Array,
                vulns: Array,
                programing_language:Array,
                framework:Array,
            },
            'largeio':{
                token: String,
                url:String,
                technologies:Array,
                vulns: Array,
                programing_language:Array,
                framework:Array,
            },
            'wafw00f':{
                token: String,
                url:String,
                waf:Array
            },
            'wpscan':{
                token: String,
                url:String,
                wp:Array,
                vulns: Array
            },
            'droopescan':{
                token: String,
                url:String,
                droop:Array,
                vulns: Array
            },
            'joomscan':{
                token: String,
                url:String,
                joomscan:Array,
                vulns: Array
            },
            'nikto':{
                token: String,
                url:String,
                nikto:Array,
                vulns: Array
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
                server:Object,
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
                programing_language:Array,
                framework:Array,
                time_create:String,
                token: String
            },
            'search' : { 
                url: String,
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
            console.log(error)
        }
    }
    connect(){
        // connect to database
        this.db = mongoose.connect(`mongodb://${hostDatabase}:${portDatabase}/wappalyzer`, {auto_reconnect: true, poolSize: 5, useNewUrlParser: true, useUnifiedTopology: true }).catch(error=>{
            console.log(error)
        })
        //console.log("[*] connection successfully")
    }
    disconnect(){
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
    createModel(){
        // create model of the table
        try {
            this.modelTable = mongoose.model(this.table, this.mapSchema[this.table])
        } catch (error){
            console.log(error)
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
                console.log(err.stack)
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
        return await await this.modelTable.find({}).elemMatch(field, condition);
    }

    async delete(target){
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