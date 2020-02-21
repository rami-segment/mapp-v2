// This destinations sends data to https://requestbin.com/ for introspection
// Create a request bin and update this endpoint


/**
 * onTrack takes a Track event and POSTs it to an external API with fetch()
 *
 * @param {SpecTrack} event The track event
 * @param {Object.<string, any>} settings Custom settings
 * @return any
 */


/**
 * 
 * @param {*} event 
 * @param {*} settings 
 * let integration_id = "9b4b1a00-107a-4e63-9ee9-69fc0cc1a45c"
 * const endpoint = new URL(`https://jamie.c.shortest-route.com/charon/api/v1/integration/${integration_id}/event?subtype=user`)
 * let secret_key = "olhw7pDZvtuyWOCxdfEAi9AAnsVoGGEW"
 */
async function onIdentify(event, settings) {

    let buildRequestHash = async (request_uri, request_body, query_string) => {
        let request_body_string = JSON.stringify(request_body)
        let request_data = request_uri.toString() + "|" + request_body_string + "|" + query_string.toString()

        let hash = crypto.createHash('sha1')
        let request_hash = hash.update(request_data).digest('hex');

        return request_hash
    }

    let encodeParams = async (param) => {
        let encodedValue = Buffer.from(JSON.stringify(param)).toString('base64').replace('+', '-').replace('/', '_').replace(/=+$/, '');
        return encodedValue
    }

    const request_uri = `/api/v1/integration/${settings.integrationId}/event`
    const request_body = event.traits;
    const query_string = "subtype=user"

    request_body.alternateEmail = request_body.email
    request_body.segmentUserId = event.userId
    request_body.identifier = event.userId + "_" + settings.marketingProgramNumber
    request_body.email = request_body.identifier + "@fakedomain.com"


    const jwtHeader = {
        "alg": "HS256"
    }

    const jwtBody = {
        "request-hash": request_hash,
        "exp": Date.now() + 10000
    }

    let request_hash = await buildRequestHash(request_uri, request_body, query_string)
    const encodedBody = await encodeParams(jwtBody);
    const encodedHeader = await encodeParams(jwtHeader);



    const signature = crypto.createHmac('sha256', settings.apiKey).update(encodedHeader + '.' + encodedBody).digest('base64').replace('+', '-').replace('/', '_').replace(/=+$/, '');

    const jwt = `${encodedHeader}.${encodedBody}.${signature}`




    const res = await fetch(settings.endpoint, {
        body: JSON.stringify(request_body),
        headers: new Headers({
            "Content-Type": "application/json",
            "auth-token": jwt
        }),
        method: "post",
    })

    return await res.text() // or res.text() for non-JSON APIs
}

async function onDelete(event, settings) {
    let identifier = event.userId + "_" + settings.marketingProgramNumber

    const getMappUser = async () => {
        const endpoint = `https://columbus.shortest-route.com/pngdev_ecm/api/rest/v4/user/getByIdentifier?identifier=${identifier}`
        const url = new URL(endpoint);
        const res = await fetch(url.toString(), {
            headers: new Headers({
                "Authorization": 'Basic ' + btoa(`${settings.restApiUsername}:${settings.restApiPassword}`),
                "Content-Type": "application/json",
                "Accept": "application/json"
            }),
            method: "get",
        })
        if (res.ok === false) {
            return null
        } else {
            return res.json()
        }

    }
    let mappUser = await getMappUser();
    let mappUserId = _.get(mappUser, "id").toString();
    
    const deleteMappUser = async () => {
        const endpoint = `https://columbus.shortest-route.com/pngdev_ecm/api/rest/v1/user/delete?userId=${mappUserId}`
        console.log(endpoint)
        const url = new URL(endpoint);
        const res = await fetch(url.toString(), {
            headers: new Headers({
                "Authorization": 'Basic ' + btoa(`${settings.restApiUsername}:${settings.restApiPassword}`),
                "Content-Type": "application/json",
                "Accept": "application/json"
            }),
            method: "delete",
        })
        if (res.ok === false) {
            return res.statusText
        } else {
            return ["user deleted in mapp"]
        }

    }
    return await deleteMappUser();

}

async function onTrack(event, settings) {

    if ((event.event != "Audience Entered" & event.event != "Audience Exited") || event.properties.audience_key != "emailContactable") {
    } else {
        let requestBody = {}
        requestBody.email = event.userId + "_" + settings.marketingProgramNumber + "@fakedomain.com"
        requestBody[settings.contactableAudienceName] = event.properties[settings.contactableAudienceName]

        const endpoint = new URL(`https://jamie.c.shortest-route.com/charon/api/v1/integration/${settings.integrationId}/event?subtype=user`)
        const request_uri = `/api/v1/integration/${settings.integrationId}/event`
        const request_body = event.properties;
        const query_string = "subtype=user"


        let encodeParams = function (param) {
            let encodedValue = Buffer.from(JSON.stringify(param)).toString('base64').replace('+', '-').replace('/', '_').replace(/=+$/, '');
            return encodedValue
        }
        let request_body_string = JSON.stringify(request_body)
        let request_data = request_uri.toString() + "|" + request_body_string + "|" + query_string.toString()
        let hash = crypto.createHash('sha1')
        let request_hash = hash.update(request_data).digest('hex');

        const jwtHeader = {
            "alg": "HS256"
        }

        const jwtBody = {
            "request-hash": request_hash,
            "exp": Date.now() + 10000
        }

        const encodedBody = encodeParams(jwtBody);
        const encodedHeader = encodeParams(jwtHeader);

        const signature = crypto.createHmac('sha256', settings.apiKey).update(encodedHeader + '.' + encodedBody).digest('base64').replace('+', '-').replace('/', '_').replace(/=+$/, '');

        const jwt = `${encodedHeader}.${encodedBody}.${signature}`


        const res = await fetch(endpoint, {
            body: JSON.stringify(request_body),
            headers: new Headers({
                "Content-Type": "application/json",
                "auth-token": jwt
            }),
            method: "post",
        });
        let response = await res.text();
        console.log(response);
        return response;



    }



}