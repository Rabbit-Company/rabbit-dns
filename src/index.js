import { Hono } from 'hono';
import { cors } from 'hono/cors';
const router = new Hono();

const cache = caches.default;

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
	const query = new URL(request.req.url).search;
	let contentType = request.req.header('Accept') || 'application/dns-message';
	if(contentType === 'application/dns-json') return await processJsonFormat(getDnsProvider(request.req.url), query);
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