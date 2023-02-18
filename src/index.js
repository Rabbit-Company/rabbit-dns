import { Hono } from 'hono';
import { cors } from 'hono/cors';
const router = new Hono();

async function processWireFormat(query){
	const message = await fetch('https://cloudflare-dns.com/dns-query' + query, { headers: { 'Accept': 'application/dns-message' } });
	if(message.status !== 200) return new Response(null, { status: message.status });
	return new Response(message.body, { headers: { 'Content-Type': 'application/dns-message', 'Access-Control-Allow-Origin': '*' } });
}

async function processJsonFormat(query){
	const message = await fetch('https://cloudflare-dns.com/dns-query' + query, { headers: { 'Accept': 'application/dns-json' } });
	if(message.status !== 200) return new Response(null, { status: message.status });
	return new Response(message.body, { headers: { 'Content-Type': 'application/dns-json', 'Access-Control-Allow-Origin': '*' } });
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
	if(contentType === 'application/dns-json') return await processJsonFormat(query);
	return await processWireFormat(query);
});

router.post('/dns-query', async request => {
	const query = await request.req.arrayBuffer();
	const message = await fetch('https://cloudflare-dns.com/dns-query', { method: 'POST', headers: { 'Content-Type': 'application/dns-message' }, body: query });
	if(message.status !== 200) return new Response(null, { status: message.status });
	return new Response(message.body, { headers: { 'Content-Type': 'application/dns-message', 'Access-Control-Allow-Origin': '*' } });
});

export default router;