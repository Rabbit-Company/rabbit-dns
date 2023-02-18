import { Hono } from 'hono';
const router = new Hono();
const cache = caches.default;

async function generateHash(message){
	const msgUint8 = new TextEncoder().encode(message);
	const hashBuffer = await crypto.subtle.digest('SHA-256', msgUint8);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function setValue(key, value, cacheTime = 60){
	let cacheKey = "https://dns.rabbitdns.org?key=" + key;
	let nres = new Response(value);
	nres.headers.append('Cache-Control', 's-maxage=' + cacheTime);
	await cache.put(cacheKey, nres);
}

async function getValue(key){
	let value = null;
	let cacheKey = "https://dns.rabbitdns.org?key=" + key;
	let res = await cache.match(cacheKey);
	if(res) value = await res.text();
	return value;
}

async function processWireFormat(query){
	const hash = await generateHash(query);
	let value = await getValue('wire-' + hash);
	if(value !== null) return new Response(value, { headers: { 'Content-Type': 'application/dns-message', 'Access-Control-Allow-Origin': '*', 'Access-Control-Max-Age': '86400' } });
	const message = await fetch('https://cloudflare-dns.com/dns-query' + query, { headers: { 'Accept': 'application/dns-message' } });
	if(message.status !== 200) return new Response(null, { status: message.status });
	const [v1, v2] = message.body.tee();
	await setValue('wire-' + hash, v1);
	return new Response(v2, { headers: { 'Content-Type': 'application/dns-message', 'Access-Control-Allow-Origin': '*', 'Access-Control-Max-Age': '86400' } });
}

async function processJsonFormat(query){
	const hash = await generateHash(query);
	let value = await getValue('json-' + hash);
	if(value !== null) return new Response(value, { headers: { 'Content-Type': 'application/dns-json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Max-Age': '86400' } });
	const message = await fetch('https://cloudflare-dns.com/dns-query' + query, { headers: { 'Accept': 'application/dns-json' } });
	if(message.status !== 200) return new Response(null, { status: message.status });
	const [v1, v2] = message.body.tee();
	await setValue('json-' + hash, v1);
	return new Response(v2, { headers: { 'Content-Type': 'application/dns-json', 'Access-Control-Allow-Origin': '*', 'Access-Control-Max-Age': '86400' } });
}

router.get('/dns-query', async request => {
	const query = new URL(request.req.url).search;
	let contentType = request.req.header('Accept') || 'application/dns-message';
	if(contentType === 'application/dns-json') return await processJsonFormat(query);
	return await processWireFormat(query);
});

router.post('/dns-query', async request => {
	const query = await request.req.arrayBuffer();
	const hash = await generateHash(new TextDecoder().decode(query));
	let value = await getValue('wirePost-' + hash);
	if(value !== null) return new Response(value, { headers: { 'Content-Type': 'application/dns-message', 'Access-Control-Allow-Origin': '*', 'Access-Control-Max-Age': '86400' } });
	const message = await fetch('https://cloudflare-dns.com/dns-query', { method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: query });
	if(message.status !== 200) return new Response(null, { status: message.status });
	const [v1, v2] = message.body.tee();
	await setValue('wirePost-' + hash, v1);
	return new Response(v2, { headers: { 'Content-Type': 'application/dns-message', 'Access-Control-Allow-Origin': '*', 'Access-Control-Max-Age': '86400' } });
});

export default router;