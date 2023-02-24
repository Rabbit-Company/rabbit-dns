import { Hono } from 'hono';
import { cors } from 'hono/cors';
const router = new Hono();

const cache = caches.default;
const rrTypes = {'A':1,'NS':2,'MD':3,'MF':4,'CNAME':5,'SOA':6,'MB':7,'MG':8,'MR':9,'NULL':10,'WKS':11,'PTR':12,'HINFO':13,'MINFO':14,'MX':15,'TXT':16,'RP':17,'AFSDB':18,'X25':19,'ISDN':20,'RT':21,'NSAP':22,'NSAP-PTR':23,'SIG':24,'KEY':25,'PX':26,'GPOS':27,'AAAA':28,'LOC':29,'NXT':30,'EID':31,'NIMLOC':32,'SRV':33,'ATMA':34,'NAPTR':35,'KX':36,'CERT':37,'A6':38,'DNAME':39,'SINK':40,'OPT':41,'APL':42,'DS':43,'SSHFP':44,'IPSECKEY':45,'RRSIG':46,'NSEC':47,'DNSKEY':48,'DHCID':49,'NSEC3':50,'NSEC3PARAM':51,'TLSA':52,'SMIMEA':53,'HIP':55,'NINFO':56,'RKEY':57,'TALINK':58,'CDS':59,'CDNSKEY':60,'OPENPGPKEY':61,'CSYNC':62,'ZONEMD':63,'SVCB':64,'HTTPS':65,'SPF':99,'UINFO':100,'UID':101,'GID':102,'UNSPEC':103,'NID':104,'L32':105,'L64':106,'LP':107,'EUI48':108,'EUI64':109,'TKEY':249,'TSIG':250,'IXFR':251,'AXFR':252,'MAILB':253,'MAILA':254,'*':255,'URI':256,'CAA':257,'AVC':258,'DOA':259,'AMTRELAY':260,'TA':32768,'DLV':32769};

function jsonResponse(json, statusCode = 200){
	if(typeof(json) !== 'string') json = JSON.stringify(json);
	return new Response(json, {
		headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*'},
		status: statusCode
	});
}

async function generateHash(message){
	const msgUint8 = new TextEncoder().encode(message);
	const hashBuffer = await crypto.subtle.digest('MD5', msgUint8);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

function isHostnameValid(hostname){
	if(typeof(hostname) !== 'string' || hostname === null) return false;
	if(!(/^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$/.test(hostname))) return false;
	return true;
}

function isProfileValid(profile){
	if(typeof(profile) !== 'object') return false;
	if(typeof(profile.blocked) !== 'object') return false;
	if(!Array.isArray(profile.blocked)) return false;

	for(let i = 0; i < profile.blocked.length; i++){
		if(!isHostnameValid(profile.blocked[i])) return false;
	}

	return true;
}

function isMD5Valid(hash){
	if(typeof(hash) !== 'string' || hash === null) return false;
	return hash.length === 32;
}

async function setValue(env, key, value, expirationTime = null, cacheTime = 60){
	let cacheKey = "https://dns.bloggy.io?key=" + key;
	if(expirationTime === null){
		await env.KV.put(key, value);
	}else{
		await env.KV.put(key, value, { expirationTtl: expirationTime });
	}
	let nres = new Response(value);
	nres.headers.append('Cache-Control', 's-maxage=' + cacheTime);
	await cache.put(cacheKey, nres);
}

async function getValue(env, key, cacheTime = 60){
	let value = null;

	let cacheKey = "https://dns.bloggy.io?key=" + key;
	let res = await cache.match(cacheKey);
	if(res) value = await res.text();

	if(value == null){
		value = await env.KV.get(key, { cacheTtl: cacheTime });
		let nres = new Response(value);
		nres.headers.append('Cache-Control', 's-maxage=' + cacheTime);
		if(value != null) await cache.put(cacheKey, nres);
	}

	return value;
}

async function deleteValue(env, key){
	await env.KV.delete(key);
	await cache.delete("https://dns.bloggy.io?key=" + key);
}

async function processWireFormat(dnsProvider, query){
	const message = await fetch(dnsProvider + query, { headers: { 'Accept': 'application/dns-message' } });
	if(message.status !== 200) return new Response(null, { status: message.status });
	return new Response(message.body, { headers: { 'Content-Type': 'application/dns-message', 'Access-Control-Allow-Origin': '*' } });
}

async function processJsonFormat(dnsProvider, query){
	const message = await fetch(dnsProvider + query, { headers: { 'Accept': 'application/dns-json' } });
	if(message.status !== 200) return new Response(null, { status: message.status });
	return new Response(message.body, { headers: { 'Content-Type': 'application/dns-json', 'Access-Control-Allow-Origin': '*' } });
}

async function processProfileJsonFormat(dnsProvider, query, profile){
	const urlParams = new URLSearchParams(query);
	const name = urlParams.get('name');
	const type = urlParams.get('type') || 'A';

	if(profile.blocked.includes(name)){
		const refusedResponse = {
			"Status": 5,
			"TC": false,
			"RD": true,
			"RA": true,
			"AD": false,
			"CD": false,
			"Question": [{
				"name": name,
				"type": rrTypes[type] || 1
			}]
		};
		return new Response(JSON.stringify(refusedResponse), { headers: { 'Content-Type': 'application/dns-json', 'Access-Control-Allow-Origin': '*' } });
	}

	const message = await fetch(dnsProvider + query, { headers: { 'Accept': 'application/dns-json' } });
	if(message.status !== 200) return new Response(null, { status: message.status });
	return new Response(message.body, { headers: { 'Content-Type': 'application/dns-json', 'Access-Control-Allow-Origin': '*' } });
}

function getDnsProvider(url){
	const hostname = new URL(url).hostname;
	let dnsProvider = "https://cloudflare-dns.com/dns-query";
	if(hostname === 'family.rabbitdns.org') dnsProvider = "https://family.cloudflare-dns.com/dns-query";
	if(hostname === 'security.rabbitdns.org') dnsProvider = "https://security.cloudflare-dns.com/dns-query";
	return dnsProvider;
}

router.use('*', cors({
		origin: '*',
		allowHeaders: ['*'],
		allowMethods: ['POST', 'GET', 'OPTIONS']
	})
);

router.get('/dns-query', async request => {
	const hostname = new URL(request.req.url).hostname;
	const query = new URL(request.req.url).search;
	let contentType = request.req.header('Accept') || 'application/dns-message';

	// Profiles
	if(isMD5Valid(hostname.split('.')[0])){
		let profile = await getValue(request.env, hostname.split('.')[0], 3600);
		if(profile === null) return new Response(null, { status: 400 });

		profile = JSON.parse(profile);
		if(contentType === 'application/dns-json'){
			return await processProfileJsonFormat(getDnsProvider(request.req.url), query, profile);
		}

		return jsonResponse({'error': 1060, 'info': 'debug', 'data': { 'hostname': hostname, 'query': query, 'profile': profile}});
	}

	// JSON Format
	if(contentType === 'application/dns-json'){
		return await processJsonFormat(getDnsProvider(request.req.url), query);
	}

	// Wire Format
	return await processWireFormat(getDnsProvider(request.req.url), query);
});

router.post('/dns-query', async request => {
	const query = await request.req.arrayBuffer();
	const message = await fetch(getDnsProvider(request.req.url), { method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: query });
	if(message.status !== 200) return new Response(null, { status: message.status });
	return new Response(message.body, { headers: { 'Content-Type': 'application/dns-message', 'Access-Control-Allow-Origin': '*' } });
});

router.post('/createProfile', async request => {
	let profile;
	try{
		profile = await request.req.json();
	}catch{
		return jsonResponse({'error': 1050, 'info': 'Provided JSON is invalid!'});
	}

	if(!isProfileValid(profile)) return jsonResponse({'error': 1050, 'info': 'Profile is invalid!'});

	profile.blocked.sort();

	const id = await generateHash(JSON.stringify(profile));
	await setValue(request.env, id, JSON.stringify(profile));
	return jsonResponse({'error': 0, 'info': 'Success', 'data': { 'id': id }});
});

export default router;