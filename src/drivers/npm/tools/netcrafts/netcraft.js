const axios = require('axios');
const cheerio = require('cheerio');
const format = require('html-format')

function getDataNetwork(url) {
    let network = axios.get(`https://sitereport.netcraft.com/?url=${url}`)
    return network
}

function getDataDcg(url) {
    let dcg = axios.get(`https://sitereport.netcraft.com/?url=${url}&ajax=dcg`);
    return dcg
}

function getDataUptime(url) {
    let uptime = axios.get(`https://sitereport.netcraft.com/?url=${url}&ajax=uptime`);
    return uptime
}

async function processNetwork(url) {
    try {
        let responseNetwork = await getDataNetwork(url);

        let $ = cheerio.load(responseNetwork.data);

        let network = {}

        //Get <div> tag which contains network information
        let contextDiv = $('#network_table_section .table--multi');

        //Each <tr> tag is a part of network information
        let contextTr = $('tr', contextDiv);

        for (let i = 0; i < contextTr.length - 1; i++) {

            let name = "";
            let value = "";

            //Get the name
            contextTh = $('th', contextTr[`${i}`]);
            name = contextTh['0'].children[0].data.trim();

            //Get the value
            contextTd = $('td', contextTr[`${i}`]);

            //If name is Hosting country
            if (name === 'Hosting country') {
                contextSpan = $('#advertised_country', contextTd);
                value = contextSpan['0'].children[0].data.trim();

            //If name is Ipv4 address
            } else if (name === 'IPv4 address') {
                contextSpan = $('#ip_address', contextTd);
                value = contextSpan['0'].children[0].data.trim();

            //Other cases
            } else {
                contextA = $('a', contextTd);
                if (contextA.length > 0) {
                    value = contextA['0'].children[0].data.trim();
                } else {
                    try {
                        value = contextTd['0'].children[0].data.trim();
                    } catch {
                        value = "";
                    }
                }
            }

            network[name] = value;
        }

        return network;

    } catch {
        return "Can not load Network data";
    }

}

async function processUptime(url) {
    try {
        const responseUptime = await getDataUptime(url);

        //Hosting History information
        let $ = cheerio.load(responseUptime.data.history_table);

        let elements = ['owner', 'ip', 'os', 'web server', 'last seen'];

        results = [];

        //Every history in <tr> , <td> tag
        let contextTr = $('tr', $('tbody'));
        for (let i = 0; i < contextTr.length; i++) {
            temp = {}

            //Each <td> tag contains information
            let elementTd = $('td', contextTr[i]);

            for (let j = 0; j < elementTd.length; j++) {

                //The first td need to be processed seperatelys
                if (j == 0) {
                    let elementA = $('a', elementTd['0']);
                    temp[elements[j]] = elementA['0'].children[0].data || "";
                } else {
                    temp[elements[j]] = elementTd[`${j}`].children[0].data;
                }
            }
            //Add hosting history to results
            results.push(temp);
        }

        //Return history hosting results
        return results;

    } catch (err) {
        return "Can not load Uptime data";
    }
}

async function processDcg(url) {
    try {
        let responseDcg = await getDataDcg(url);

        let $ = cheerio.load(responseDcg.data.background_table);

        let results = [];

        //Background information
        let background = {};
        let contextTr = $('tr', $('tbody'));
        for (let i = 0; i < contextTr.length; i++) {

            let name = "";
            let value = "";

            //Get the name
            contextTh = $('th', contextTr[`${i}`]);
            name = contextTh['0'].children[0].data.trim();

            //Get the value
            contextTd = $('td', contextTr[`${i}`]);

            //Process with the case Site rank
            if (i === 1) {
                contextA = $('a', contextTd);
                if (contextA.length > 0) {
                    value = contextA[`${0}`].children[0].data.trim();
                } else {
                    value = "";
                }

                //Process with the case Netcraft Risk Rating
            } else if (i == 4) {
                contextSpan = $('.risk_label', contextTd);
                value = contextSpan[`0`].children[0].data.trim();
            } else {
                try {
                    value = contextTd['0'].children[0].data.trim();
                } catch {
                    value = "";
                }
            }

            background[`${name}`] = value;

        }

        //Site Technology infomation
        $ = cheerio.load(responseDcg.data.technology_table);
        let technologies = [];

        for (let i = 0; i < $('li').length; i++) {

            //Each <li> tag is a type of technology
            //The name of type of technology in <h3> tag
            let context = $('li')[i];
            let technologyType = $('h3', context).html();

            //technology[`${technologyType}`] = [];

            //Detail technology is in <tbody>, <tr>, <span>
            //Get all <tr> tag
            let contextTr = $('tr', $('tbody', context));
            for (let j = 0; j < contextTr.length; j++) {
                temp = {}

                //Get all <span> in that <tr> tag
                let elementSpan = $('span', contextTr[j]);

                //temp['technology'] = elementSpan[0].children[0].data;
                temp['name'] = elementSpan[0].children[0].data;

                //In case it doesn't have description
                try {
                    temp['description'] = elementSpan[1].children[0].data || "";
                } catch {
                    temp['description'] = "";
                }

                //In case it doesn't have link
                try {
                    temp['link'] = elementSpan[0].children[1].attribs.href || "";
                } catch {
                    temp['link'] = "";
                }

                //Popular sites information
                temp['popular-site'] = [];
                let elementA = $('a', elementSpan[2]);
                for (let k = 0; k < elementA.length; k++) {
                    let tempSite = {}
                    tempSite['site'] = elementA[`${k}`].children[0].data;
                    temp['popular-site'].push(tempSite);
                }

                //Add technology to results
                //technology[`${technologyType}`].push(temp);
                technologies.push(temp);
            }
        }

        results[0] = background;
        results[1] = technologies;
        return results;

    } catch {
        return "Can not load Dcg data";
    }

}

exports.netcraft = async function processUrl(url) {
    let results = {};
    let responseDcg = await processDcg(url);
    let responseUptime = await processUptime(url);
    let responseNetwork = await processNetwork(url);

    results['background'] = responseDcg[0];
    results['network'] = responseNetwork;
    results['hosting history'] = responseUptime;
    results['technologies'] = responseDcg[1];

    //Return a Promise
    return new Promise((resolve, reject) => {
        resolve(JSON.stringify(results));
    })
}