import { Hono } from 'hono';
import { cors } from 'hono/cors';
const router = new Hono();

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

export default router;