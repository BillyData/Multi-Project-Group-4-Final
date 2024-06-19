const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;
const cors = require('cors');
var IotApi = require('@arduino/arduino-iot-client');
var rp = require('request-promise');

app.use(cors());

async function getToken() {
    var options = {
        method: 'POST',
        url: 'https://api2.arduino.cc/iot/v1/clients/token',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        timeout: 300000,
        json: true,
        form: {
            grant_type: 'client_credentials',
            client_id: 'qd0E6GA9O9ygvxRg4vE5Kom3k0bzPxRU',
            client_secret: 'HVIcE6E4XBaaea9ZDoa4KoubbIyr9c3eAa4lZN9SgRL6AGo47UrDHr7ZLqD3hQ4x',
            audience: 'https://api2.arduino.cc/iot'
        }
    };

    try {
        const response = await rp(options);
        return response['access_token'];
    }
    catch (error) {
        console.error("Failed getting an access token: " + error)
    }
}

async function listProperties() {
    var client = IotApi.ApiClient.instance;
    // Configure OAuth2 access token for authorization: oauth2
    var oauth2 = client.authentications['oauth2'];
    oauth2.accessToken = await getToken();

    var api = new IotApi.PropertiesV2Api(client)
    var id1 = "bbad631b-2f73-42ac-ae87-a3772c197a23"; // {String} The id of the thing
    var id2 = "4f8e86a9-16a5-409e-a599-ba781723cca4";
    var id3 = "473e551a-8e4b-4500-867e-0d6b4c8e97ff";

    var opts = {
        'showDeleted': true // {Boolean} If true, shows the soft deleted properties
    };

    try {
        const data1 = await api.propertiesV2List(id1, opts);
        const data2 = await api.propertiesV2List(id2, opts);
        const data3 = await api.propertiesV2List(id3, opts);
        console.log([[id1, data1], [id2, data2], [id3, data3]])
        return [[id1, data1], [id2, data2], [id3, data3]];
    } catch (error) {
        console.error("Error fetching properties:", error);
        throw error;
    }
}


app.get('/arduino-data', async (req, res) => {
    try {
        const data = await listProperties();
        res.json(data); // Sending JSON response to the client
    } catch (error) {
        res.status(500).send("Error fetching Arduino data"); // Sending error response if something goes wrong
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});