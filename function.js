// onAlias --> hit profile API with userId --> send identify with all traits to
// mapp (same logic as onIdentify flow that's already in place) send delete to
// Mapp (same logic as onDelete flow that's already in place)

// getMappUser function returns Mapp user for deletion. It blocks until the
// request is successful. If it takes more than ~5 seconds, this Destination
// Function will be cancelled and retried later. This will help us smooth over
// the race condition where we create a user in Mapp's API but it takes another
// few minutes for Mapp to return that user here.

async function getMappUser(identifier, settings) {
	// Set up Mapp endpoint: Engage API
	const endpoint = `https://columbus.shortest-route.com/${settings.mappInstance}/api/rest/v13/user/getByIdentifier?identifier=${identifier}`;
	const url = new URL(endpoint);

	while (true) {
		const res = await fetch(url.toString(), {
			headers: new Headers({
				Authorization:
					'Basic ' +
					btoa(`${settings.restApiUsername}:${settings.restApiPassword}`),
				'Content-Type': 'application/json',
				Accept: 'application/json'
			}),
			method: 'get'
		});

		console.log(
			`getMappUser(${identifier}) = `,
			res.ok,
			res.status,
			res.statusText
		);

		if (res.ok) {
			return res.json();
		} else {
			let mapp_res_body = await res.text();
			console.log(mapp_res_body);
			console.log('Retrying in 500ms...');
			await new Promise(r => setTimeout(r, 500));
		}
	}
}

// Function deleteMappUser sends delete user (by "email") request to Mapp.
// If request returns !200, it throws an error.
async function deleteMappUser(userId, marketingProgramNumber, settings) {
	const endpoint = `https://jamie.c.shortest-route.com/charon/api/v1/integration/${settings.integrationId}/event?subtype=user`;
	const request_uri = `/api/v1/integration/${settings.integrationId}/event`;
	const query_string = 'subtype=user';

	let mapp_email_key =
		userId + '_' + marketingProgramNumber + '@fakedomain.com';
	let request_body = {
		email: mapp_email_key,
		delete: 'true'
	};

	let request_body_string = JSON.stringify(request_body);
	let request_data =
		request_uri.toString() +
		'|' +
		request_body_string +
		'|' +
		query_string.toString();

	console.log(request_data);

	let hash = crypto.createHash('sha1');
	let request_hash = hash.update(request_data).digest('hex');

	const jwtHeader = {
		alg: 'HS256'
	};

	const jwtBody = {
		'request-hash': request_hash,
		exp: Date.now() + 600000
	};
	let encodeParams = function(param) {
		let encodedValue = Buffer.from(JSON.stringify(param))
			.toString('base64')
			.replace('+', '-')
			.replace('/', '_')
			.replace(/=+$/, '');
		return encodedValue;
	};
	const encodedBody = encodeParams(jwtBody);
	const encodedHeader = encodeParams(jwtHeader);
	const signature = crypto
		.createHmac('sha256', settings.apiKey)
		.update(encodedHeader + '.' + encodedBody)
		.digest('base64')
		.replace('+', '-')
		.replace('/', '_')
		.replace(/=+$/, '');

	const jwt = `${encodedHeader}.${encodedBody}.${signature}`;

	const res = await fetch(endpoint, {
		body: request_body_string,
		headers: new Headers({
			'Content-Type': 'application/json',
			'auth-token': jwt
		}),
		method: 'post'
	});

	console.log(
		`deleteMappUser(${mapp_email_key}) = `,
		res.ok,
		res.status,
		res.statusText
	);

	if (res.ok) {
		console.log(
			'Mapp Delete user OK. User Mapp Key: ',
			mapp_email_key,
			res.status,
			res.statusText
		);
		console.log('Payload:', JSON.stringify(request_body));
	} else {
		let mapp_res_body = await res.text();
		console.log('DELETE response =', mapp_res_body);
		throw new Error(`DELETE ${endpoint} = ${res.statusText}`);
	}
}

/**
 * Handle identify event
 * @param  {SegmentIdentifyEvent} event
 * @param  {FunctionSettings} settings
 */
async function onIdentify(event, settings) {
	if (!event.traits) {
		return;
	} else {
		const endpoint = new URL(
			`https://jamie.c.shortest-route.com/charon/api/v1/integration/${settings.integrationId}/event?subtype=user`
		);
		const request_uri = `/api/v1/integration/${settings.integrationId}/event`;

		// updating 'registrationDate' to expected ISO format: "2020-03-09T07:18:50.12345Z" --> "2020-03-09T07:18:50.12Z"
		if (event.traits.registrationDate) {
			let regDate = event.traits.registrationDate;
			let re = /(?<dateTime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?<decimals>\.\d{0,2})?)\d*(?<Z>Z)/;
			let m = regDate.match(re);
			console.log(m);
			if (m != null) {
				let newRegDate = m.groups.dateTime + m.groups.Z;
				event.traits.registrationDate = newRegDate;
			}
			//delete personasUser.traits.registrationDate
		}

		const request_body = event.traits;
		const query_string = 'subtype=user';

		let encodeParams = function(param) {
			let encodedValue = Buffer.from(JSON.stringify(param))
				.toString('base64')
				.replace('+', '-')
				.replace('/', '_')
				.replace(/=+$/, '');
			return encodedValue;
		};

		if (request_body.email) {
			request_body.alternateEmail = request_body.email;
		}
		request_body.segmentUserId = event.userId;
		request_body.identifier =
			event.userId + '_' + settings.marketingProgramNumber;
		request_body.email = request_body.identifier + '@fakedomain.com';
		request_body.group = settings.group;
		// if(request_body.sourceId){
		//     request_body.sourceId = parseInt(request_body.sourceId)
		// }

		//console.log('request_body');
		//console.log(request_body);

		let request_body_string = JSON.stringify(request_body);
		let request_data =
			request_uri.toString() +
			'|' +
			request_body_string +
			'|' +
			query_string.toString();
		console.log(request_data);
		let hash = crypto.createHash('sha1');
		let request_hash = hash.update(request_data).digest('hex');

		const jwtHeader = {
			alg: 'HS256'
		};

		const jwtBody = {
			'request-hash': request_hash,
			exp: Date.now() + 600000
		};

		//let request_hash = await buildRequestHash(request_uri, request_body, query_string)
		const encodedBody = encodeParams(jwtBody);
		const encodedHeader = encodeParams(jwtHeader);
		const signature = crypto
			.createHmac('sha256', settings.apiKey)
			.update(encodedHeader + '.' + encodedBody)
			.digest('base64')
			.replace('+', '-')
			.replace('/', '_')
			.replace(/=+$/, '');

		const jwt = `${encodedHeader}.${encodedBody}.${signature}`;
		// console.log("jwt: " + jwt)
		// console.log("hash: " + request_hash)

		const res = await fetch(endpoint, {
			body: JSON.stringify(request_body),
			headers: new Headers({
				'Content-Type': 'application/json',
				'auth-token': jwt
			}),
			method: 'post'
		});

		if (res.ok) {
			console.log(
				'onIdentify Mapp create user OK. User identifier: ',
				request_body.identifier,
				res.status,
				res.statusText
			);
			console.log('Payload:', JSON.stringify(request_body));
		} else {
			console.log(
				'onIdentify Mapp create user Error. User identifier: ',
				request_body.identifier,
				res.status,
				res.statusText
			);
			console.log('Payload:', JSON.stringify(request_body));
			throw new Error(`POST ${endpoint} = ${res.statusText}`);
		}
	}
}

async function onAlias(event, settings) {
	// Function updateMapp: upserts existing user profile in Mapp
	// where user_id == userId from Alias call
	console.log('Start onAlias');

	const updateMapp = async () => {
		// Prepare and emit Profile API request to pull user's traits

		//Pull user traits via Profile API
		const profileAPIEndpoint = `https://profiles.segment.com/v1/spaces/${settings.segmentSpaceId}/collections/users/profiles/user_id:${event.userId}/traits?limit=200`;
		const profileAPIReq = await fetch(profileAPIEndpoint, {
			headers: new Headers({
				Authorization: 'Basic ' + btoa(settings.segmentSpaceToken + ':'),
				'Content-Type': 'application/json'
			}),
			method: 'get'
		});

		// Handling Profile API response. If response !200, throw an error.
		if (profileAPIReq.ok) {
			console.log(
				'Profile API call OK',
				profileAPIReq.status,
				profileAPIReq.statusText
			);
		} else {
			let res_body = await profileAPIReq.text();
			console.log(
				'Error',
				profileAPIReq.status,
				profileAPIReq.statusText,
				profileAPIReq.ok
			);
			console.log(res_body);
			throw new Error(
				`GET ${profileAPIEndpoint} = ${profileAPIReq.statusText}`
			);
		}

		// Personas user traits
		const personasUser = await profileAPIReq.json();
		// console.log("Traits")
		// console.log(personasUser.traits)

		// updating 'registrationDate' to expected ISO format: "2020-03-09T07:18:50.12345Z" --> "2020-03-09T07:18:50.12Z"
		if (personasUser.traits.registrationDate) {
			let regDate = personasUser.traits.registrationDate;
			let re = /(?<dateTime>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?<decimals>\.\d{0,2})?)\d*(?<Z>\w)/;
			let m = regDate.match(re);
			console.log(m);
			if (m != null) {
				let newRegDate = m.groups.dateTime + m.groups.Z;
				personasUser.traits.registrationDate = newRegDate;
			}
		}
		const request_body = personasUser.traits;
		console.log(request_body);
		if (request_body.email) {
			request_body.alternateEmail = request_body.email;
		}
		request_body.segmentUserId = event.userId;
		request_body.identifier =
			event.userId + '_' + settings.marketingProgramNumber;
		request_body.email = request_body.identifier + '@fakedomain.com';
		request_body.group = settings.group;

		// Set up Mapp endpoint and credentials
		const endpoint = new URL(
			`https://jamie.c.shortest-route.com/charon/api/v1/integration/${settings.integrationId}/event?subtype=user`
		);
		const request_uri = `/api/v1/integration/${settings.integrationId}/event`;
		const query_string = 'subtype=user';

		let encodeParams = function(param) {
			let encodedValue = Buffer.from(JSON.stringify(param))
				.toString('base64')
				.replace('+', '-')
				.replace('/', '_')
				.replace(/=+$/, '');
			return encodedValue;
		};

		// Generate Mapp request to create a new user profile:  with the traits from Profile API
		let request_body_string = JSON.stringify(request_body);
		let request_data =
			request_uri.toString() +
			'|' +
			request_body_string +
			'|' +
			query_string.toString();
		console.log(request_data);
		let hash = crypto.createHash('sha1');
		let request_hash = hash.update(request_data).digest('hex');

		const jwtHeader = {
			alg: 'HS256'
		};

		const jwtBody = {
			'request-hash': request_hash,
			exp: Date.now() + 600000
		};

		//let request_hash = await buildRequestHash(request_uri, request_body, query_string)
		const encodedBody = encodeParams(jwtBody);
		const encodedHeader = encodeParams(jwtHeader);
		const signature = crypto
			.createHmac('sha256', settings.apiKey)
			.update(encodedHeader + '.' + encodedBody)
			.digest('base64')
			.replace('+', '-')
			.replace('/', '_')
			.replace(/=+$/, '');

		const jwt = `${encodedHeader}.${encodedBody}.${signature}`;
		//console.log(request_body)
		//console.log("jwt: " + jwt)
		//console.log("hash: " + request_hash)

		const res = await fetch(endpoint, {
			body: JSON.stringify(request_body),
			headers: new Headers({
				'Content-Type': 'application/json',
				'auth-token': jwt
			}),
			method: 'post'
		});

		// Handling Mapp API response
		//const res_text = await res.text();
		if (res.ok) {
			console.log(
				'onAlias Mapp create user OK. User identifier: ',
				request_body.identifier,
				res.status,
				res.statusText
			);
		} else {
			let mapp_res_body = await res.text();
			console.log(
				'onAlias Mapp create user Error. User identifier: ',
				request_body.identifier,
				res.status,
				res.statusText,
				res.ok
			);
			console.log(mapp_res_body);
			throw new Error(`POST ${endpoint} = ${res.statusText}`);
		}
	};

	await updateMapp();

	// Mapp identifier for the user to be deleted
	let identifier = event.previousId + '_' + settings.marketingProgramNumber;
	console.log('Mapp user to delete: ', identifier);

	// Set up Mapp user and user id required for deletion request
	let mappUser = await getMappUser(identifier, settings);
	let mappUserId = _.get(mappUser, 'id').toString();
	console.log('mappUser', mappUser);

	// Function deleteMappUser makes delete request to Mapp
	return deleteMappUser(
		event.userId,
		settings.marketingProgramNumber,
		settings
	);
}

async function onDelete(event, settings) {
	return deleteMappUser(
		event.userId,
		settings.marketingProgramNumber,
		settings
	);
}
