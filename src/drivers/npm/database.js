'use strict'
const mongoose = require("mongoose")
const { Schema } = mongoose


class dataHandle{
    constructor(table,schema=undefined) {
        this.schemaDefault = {
            'link':{
                hostname: String,
                href: String,
                pathname: String
            },
            'tech':{
                urls:String,
                technologies: Array
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
                this.schema=this.schemaDefault[this.table]
            }
            if(this.schemaDefault[this.table] == undefined && this.schema==undefined){
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
        mongoose.connect("mongodb://localhost:27017/weppalyzer", { useNewUrlParser: true, useUnifiedTopology: true }).catch(error => {
            console.log(error)
        })
        console.log("[*] connection successfully")
    }
    
    disconnect() {
        mongoose.connection.close(() => {
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
    async addLink(obj) {
        let exist = await this.checkExist({ pathname: obj.pathname })

        if (!exist) {
            let result = new this.modelTable(obj)
            await result.save(err => {
                if (err) {
                    console.log(err)
                    return
                }
                console.log("[*] add successfully")
            })
        }
    }
    async findOne(target) {
        return await (this.modelTable.findOne(target)).exec()
    }
    async addTech(obj){
        let result = new this.modelTable(obj)
        await result.save(err => {
            if (err) {
                console.log(err)
            return
        }
        console.log("[*] add successfully")
    })
    }
    async getTable(target){
        return await this.modelTable.find({}).exec()
    }
    async delete(target) {
        // delete one function
        await this.modelTable.deleteOne(target, (err) => {
            if (err) {
                console.log(err)
                return
            }
            console.log("[*] delete successfully")
        })
    }
}

module.exports = dataHandle