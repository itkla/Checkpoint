console.log('>>> Starting jwt-test.js');

const fastify = require('fastify')();
const jwtPlugin = require('@fastify/jwt');

console.log('jwtPlugin is:', jwtPlugin);
console.log('Type of jwtPlugin:', typeof jwtPlugin);

fastify.register(jwtPlugin, {
    secret: 'test-secret',
    namespace: 'jwtUser',
}, (err) => {
    console.log('>>> In JWT plugin callback');
    if (err) {
        console.error('Registration error:', err);
    } else {
        console.log('>>> JWT plugin registered OK');
    }
});

fastify.after((err) => {
    console.log('>>> fastify.after called, err:', err);
    console.log('hasDecorator("jwtUser")?', fastify.hasDecorator('jwtUser'));
});

fastify.listen({ port: 3000 }, (err, address) => {
    if (err) {
        console.error('Listen error:', err);
        return;
    }
    console.log(`>>> Listening on ${address}`);
});
