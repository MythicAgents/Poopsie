function(task, responses){
    if(task.status.includes("error")){
        const combined = responses.reduce( (prev, cur) => {
            return prev + cur;
        }, "");
        return {'plaintext': combined};
    }else if(responses.length > 0){
        let data = "";
        let rows = [];
        let headers = [
            {"plaintext": "Status", "type": "string", "cellStyle": {}, "width": 80},
            {"plaintext": "Name", "type": "string", "cellStyle": {}, "width": 200},
            {"plaintext": "IPv4", "type": "string", "cellStyle": {}, "width": 300},
            {"plaintext": "DNS", "type": "string", "cellStyle": {}, "width": 300},
            {"plaintext": "Gateway", "type": "string", "cellStyle": {}, "width": 300},
            {"plaintext": "IPv6", "type": "string", "cellStyle": {}, "width": 300},
            {"plaintext": "More Info", "type": "button", "cellStyle": {}, "width": 100, "disableSort": true},
        ];

        try {
            data = JSON.parse(responses[0]);
        } catch (error) {
            console.log(error);
            const combined = responses.reduce((prev, cur) => {
                return prev + cur;
            }, "");
            return {'plaintext': combined};
        }
        for(let j = 0; j < data.length; j++){
            let moreInfo = "";
            let nic = data[j];

            moreInfo = nic["Description"]
            moreInfo += `\n   Adapter Name ............................ : ${nic["adapter_name"]}\n`;
            moreInfo += `   Adapter ID .............................. : ${nic["adapter_id"]}\n`;
            moreInfo += `   Adapter Status .......................... : ${nic["status"]}\n`;

            for(let i = 0; i < nic["addresses_v4"].length; i++){
                moreInfo += `   Unicast Address ......................... : ${nic["addresses_v4"][i]}\n`;
            }
            for(let i = 0; i < nic["addresses_v6"].length; i++){
                moreInfo += `   Unicast Address ......................... : ${nic["addresses_v6"][i]}\n`;
            }
            for(let i = 0; i < nic["dns_servers"].length; i++){
                moreInfo += `   DNS Servers ............................. : ${nic["dns_servers"][i]}\n`;
            }
            for(let i = 0; i < nic["gateways"].length; i++){
                moreInfo += `   Gateway Address ......................... : ${nic["gateways"][i]}\n`;
            }
            for(let i = 0; i < nic["dhcp_addresses"].length; i++){
                moreInfo += `   Dhcp Server ............................. : ${nic["dhcp_addresses"][i]}\n`;
            }
            moreInfo += `   DNS suffix .............................. : ${nic["dns_suffix"]}\n`;
            moreInfo += `   DNS enabled ............................. : ${nic["dns_enabled"]}\n`;
            moreInfo += `   Dynamically configured DNS .............. : ${nic["dynamic_dns_enabled"]}\n`;

            let backgroundColor = "";
            let rowStyle = {};
            let row = {
                "rowStyle": rowStyle,
                "Name": {"plaintext": nic["adapter_name"], "cellStyle": {}},
                "IPv4": {"plaintext": nic["addresses_v4"].toString(), "cellStyle": {}},
                "IPv6": {"plaintext": nic["addresses_v6"].toString(), "cellStyle": {}},
                "DNS": {"plaintext": nic["dns_servers"].toString(), "cellStyle": {}},
                "Gateway": {"plaintext": nic["gateways"].toString(), "cellStyle": {}},
                "Status": {"plaintext": nic["status"], "cellStyle": {}},

                "More Info": {
                    "button": {
                        "name": "Expand",
                        "type": "string",
                        "value": moreInfo,
                        "title": nic["description"],
                        "hoverText": "View additional attributes"
                    }
                }
            };

            rows.push(row);
        }

        return {"table":[{
            "headers": headers,
            "rows": rows,
            "title": "IP Configuration"
        }]};


    }else{
        // this means we shouldn't have any output
        return {"plaintext": "No response yet from agent..."}
    }
}