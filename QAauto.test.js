const app = require('./app');
const request = require('supertest');

describe('Security Tests: IDOR on /api/users/:id', () => {
    let user1Token = '';
    beforeAll(async () => {
        const res = await request(app)
            .post('/login')
            .send({ id: 1, password: 'password123' });
        
        user1Token = res.body.token;
    });
    it('should allow access to own profile (200 OK)', async () => {
        const res = await request(app)
            .get('/api/users/1')
            .set('Authorization', `Bearer ${user1Token}`);

        expect(res.statusCode).toEqual(200);
        expect(res.body.secret_data).toBe('My balance: 50 UAH');
    });

    it('should BLOCK attempt to read another profile (403 Forbidden)', async () => {
        const res = await request(app)
            .get('/api/users/2')
            .set('Authorization', `Bearer ${user1Token}`);
        expect(res.statusCode).toEqual(403);
        expect(res.body.error).toContain('Forbidden');
    });

    it('should BLOCK request without token entirely (401 Unauthorized)', async () => {
        const res = await request(app)
            .get('/api/users/1');

        expect(res.statusCode).toEqual(401);
    });
});
