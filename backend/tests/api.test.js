const request = require('supertest');
const app = require('../src/app');

describe('API Health Check', () => {
  test('GET /health should return 200', async () => {
    const response = await request(app)
      .get('/health')
      .expect(200);
    
    expect(response.body).toHaveProperty('status', 'ok');
  });
});

describe('API Base Route', () => {
  test('GET / should return API info', async () => {
    const response = await request(app)
      .get('/')
      .expect(200);
    
    expect(response.body).toHaveProperty('message', 'AutoSec API Server');
  });
});