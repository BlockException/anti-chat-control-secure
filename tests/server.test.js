const request = require('supertest');
const { createApp } = require('../server');

describe('server health', () => {
  let app;

  beforeAll(() => {
    app = createApp();
  });

  test('responds 200 on /health', async () => {
    const response = await request(app).get('/health');
    expect(response.status).toBe(200);
    expect(response.body.status).toBe('ok');
  });
});
