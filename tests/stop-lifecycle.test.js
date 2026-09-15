const assert = require('assert');
const http = require('http');
const net = require('net');
const WebSocket = require('ws');
const fs = require('fs');
const path = require('path');

async function testStopLifecycle() {
  console.log('🧪 Testing Project Stop / Hibernate Lifecycle & Process Termination...');

  const BASE_URL = 'http://localhost:3030';
  const WS_URL = 'ws://localhost:3030/ws';

  // 1. Verify API is reachable
  const healthRes = await fetch(`${BASE_URL}/api/health`);
  assert.strictEqual(healthRes.status, 200, 'Health endpoint must return 200');
  console.log('  ✓ Server is alive on port 3030');

  // 2. Connect WebSocket to verify real-time broadcasts
  const receivedWsEvents = [];
  const ws = new WebSocket(WS_URL);
  await new Promise((resolve, reject) => {
    ws.on('open', resolve);
    ws.on('error', reject);
  });
  ws.on('message', (data) => {
    try {
      const parsed = JSON.parse(data.toString());
      if (parsed.type === 'project_update') {
        receivedWsEvents.push(parsed.data);
      }
    } catch(e) {}
  });
  console.log('  ✓ WebSocket connected to receive project_update events');

  // 3. Create a dedicated temporary test project
  const testProjectPayload = {
    name: 'Lifecycle Test Project',
    description: 'Proyecto temporal para validar inicio, parada y liberación de puertos',
    icon: '⚡',
    status: 'stopped',
    localRunning: false,
    forgePort: 3991,
    citadelPort: 8991
  };
  const createRes = await fetch(`${BASE_URL}/api/projects`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(testProjectPayload)
  });
  if (createRes.status !== 201) {
    const body = await createRes.text();
    assert.fail(`Project creation must return 201, got ${createRes.status}: ${body}`);
  }
  const testProject = await createRes.json();
  const testId = testProject.id;
  console.log(`  ✓ Created test project: ${testProject.name} (${testId})`);

  try {
    // 4. Test Starting Local
    console.log('  Testing start-local...');
    const startRes = await fetch(`${BASE_URL}/api/projects/${testId}/start-local`, { method: 'POST' });
    assert.strictEqual(startRes.status, 200, 'start-local must return 200');
    const startedProject = await startRes.json();
    assert.strictEqual(startedProject.status, 'active', 'Started project must have status: active');
    assert.strictEqual(startedProject.localRunning, true, 'Started project must have localRunning: true');
    assert.ok(startedProject.localPort > 0, 'Started project must have an assigned localPort');
    const assignedPort = startedProject.localPort;
    console.log(`  ✓ Project started on localPort ${assignedPort} with status: active, localRunning: true`);

    // Verify port is actually responding HTTP 200
    await new Promise(r => setTimeout(r, 600));
    const portRes = await fetch(`http://localhost:${assignedPort}`);
    assert.strictEqual(portRes.status, 200, 'Assigned port must serve HTTP 200');
    console.log(`  ✓ Assigned port ${assignedPort} is listening and returned HTTP 200`);

    // Verify WebSocket event received for start
    const startEvent = receivedWsEvents.find(e => e.id === testId && e.localRunning === true && e.status === 'active');
    assert.ok(startEvent, 'WebSocket must have broadcasted project_update with status: active');
    console.log('  ✓ WebSocket broadcasted project_update (status: active, localRunning: true)');

    // 5. Test Stopping Project via POST /api/projects/:id/stop
    console.log('  Testing stop endpoint...');
    const stopRes = await fetch(`${BASE_URL}/api/projects/${testId}/stop`, { method: 'POST' });
    assert.strictEqual(stopRes.status, 200, 'stop must return 200');
    const stoppedProject = await stopRes.json();
    assert.strictEqual(stoppedProject.status, 'stopped', 'Stopped project must have status: stopped');
    assert.strictEqual(stoppedProject.localRunning, false, 'Stopped project must have localRunning: false');
    console.log('  ✓ Stop API returned status: stopped, localRunning: false');

    // Wait for process kill and port release
    await new Promise(r => setTimeout(r, 800));

    // Verify port is closed and freed
    const isPortClosed = await new Promise((resolve) => {
      const client = net.createConnection({ port: assignedPort, host: '127.0.0.1' }, () => {
        client.destroy();
        resolve(false); // Port is still open
      });
      client.on('error', () => resolve(true)); // Connection refused -> port is free
      client.setTimeout(1500, () => {
        client.destroy();
        resolve(true);
      });
    });
    assert.strictEqual(isPortClosed, true, `Port ${assignedPort} must be completely closed and freed after stop`);
    console.log(`  ✓ Port ${assignedPort} is confirmed completely closed and free`);

    // Verify projects.json has persisted status: 'stopped' and localRunning: false
    const projectsOnDisk = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'data', 'projects.json'), 'utf8'));
    const diskProject = projectsOnDisk.find(p => p.id === testId);
    assert.ok(diskProject, 'Project must exist in data/projects.json');
    assert.strictEqual(diskProject.status, 'stopped', 'Persisted status must be stopped');
    assert.strictEqual(diskProject.localRunning, false, 'Persisted localRunning must be false');
    console.log('  ✓ State correctly persisted in data/projects.json (status: stopped, localRunning: false)');

    // Verify WebSocket broadcast received for stop
    const stopEvent = receivedWsEvents.find(e => e.id === testId && e.localRunning === false && e.status === 'stopped');
    assert.ok(stopEvent, 'WebSocket must have broadcasted project_update with status: stopped');
    console.log('  ✓ WebSocket broadcasted project_update (status: stopped, localRunning: false)');

    // 6. Test Hibernating Project
    console.log('  Testing hibernate endpoint...');
    // Start it again first
    await fetch(`${BASE_URL}/api/projects/${testId}/start-local`, { method: 'POST' });
    await new Promise(r => setTimeout(r, 500));
    const hibernateRes = await fetch(`${BASE_URL}/api/projects/${testId}/hibernate`, { method: 'POST' });
    assert.strictEqual(hibernateRes.status, 200, 'hibernate must return 200');
    const hibernatedProject = await hibernateRes.json();
    assert.strictEqual(hibernatedProject.status, 'hibernated', 'Hibernated project must have status: hibernated');
    assert.strictEqual(hibernatedProject.localRunning, false, 'Hibernated project must have localRunning: false');
    console.log('  ✓ Hibernate API returned status: hibernated, localRunning: false');

    // Verify port is freed on hibernate
    await new Promise(r => setTimeout(r, 800));
    const isPortClosedAfterHibernate = await new Promise((resolve) => {
      const client = net.createConnection({ port: assignedPort, host: '127.0.0.1' }, () => {
        client.destroy();
        resolve(false);
      });
      client.on('error', () => resolve(true));
      client.setTimeout(1500, () => {
        client.destroy();
        resolve(true);
      });
    });
    assert.strictEqual(isPortClosedAfterHibernate, true, `Port ${assignedPort} must be freed after hibernate`);
    console.log(`  ✓ Port ${assignedPort} is confirmed completely freed after hibernate`);

    // 7. Test Activating Project via POST /api/projects/:id/activate
    console.log('  Testing activate endpoint...');
    const activateRes = await fetch(`${BASE_URL}/api/projects/${testId}/activate`, { method: 'POST' });
    assert.strictEqual(activateRes.status, 200, 'activate must return 200');
    const activatedProject = await activateRes.json();
    assert.strictEqual(activatedProject.status, 'active', 'Activated project must have status: active');
    console.log('  ✓ Activate API returned status: active');

    // 8. Test Stopping an active project when localRunning is false
    console.log('  Testing stop on active non-local project...');
    const stopNonLocalRes = await fetch(`${BASE_URL}/api/projects/${testId}/stop`, { method: 'POST' });
    assert.strictEqual(stopNonLocalRes.status, 200, 'stop non-local project must return 200');
    const stoppedNonLocal = await stopNonLocalRes.json();
    assert.strictEqual(stoppedNonLocal.status, 'stopped', 'Must transition to stopped');
    assert.strictEqual(stoppedNonLocal.localRunning, false, 'localRunning must be false');
    console.log('  ✓ Stop on active non-local project succeeded (status: stopped)');

    // 9. Test Rapid Consecutive Stop Idempotence
    console.log('  Testing rapid consecutive stop idempotence...');
    const doubleStopRes = await fetch(`${BASE_URL}/api/projects/${testId}/stop`, { method: 'POST' });
    assert.strictEqual(doubleStopRes.status, 200, 'idempotent stop must return 200 without throwing');
    const doubleStopProject = await doubleStopRes.json();
    assert.strictEqual(doubleStopProject.status, 'stopped');
    console.log('  ✓ Idempotent double stop returned 200 cleanly');

  } finally {
    // Cleanup
    ws.close();
    await fetch(`${BASE_URL}/api/projects/${testId}`, { method: 'DELETE' });
    console.log('  ✓ Cleaned up test project');
  }

  console.log('✅ All project stop/start/hibernate lifecycle tests passed successfully!\n');
}

module.exports = testStopLifecycle;

if (require.main === module) {
  testStopLifecycle().then(() => process.exit(0)).catch(err => {
    console.error(err);
    process.exit(1);
  });
}
