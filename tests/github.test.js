const assert = require('assert');
const crypto = require('crypto');
const githubService = require('../server/services/githubService');
const projectManager = require('../server/services/projectManager');
const containerOrchestrator = require('../server/services/containerOrchestrator');
const apiRouter = require('../server/routes/api');
const mcpServer = require('../server/services/mcpServer');

async function testGithub() {
  console.log('🧪 Testing GitHub Integration & Auto-Deploy Webhook Engine...');

  // Backup any existing github config
  const originalConfig = { ...githubService.config };

  try {
    // 1. Initial Status Check
    await githubService.disconnect();
    const initialStatus = githubService.getStatus();
    assert.strictEqual(initialStatus.connected, false, 'Should be disconnected initially');
    assert.strictEqual(initialStatus.user, null);
    console.log('  ✓ Initial disconnected status check passed');

    // 2. Token Verification (Mock & Validation)
    await assert.rejects(
      async () => await githubService.verifyToken(''),
      /token de GitHub es obligatorio/i,
      'Empty token should be rejected'
    );

    const verifiedUser = await githubService.verifyToken('ghp_mock_token_for_testing_12345');
    assert.ok(verifiedUser, 'Verified user should be returned');
    assert.strictEqual(verifiedUser.login, 'pablo-developer');
    assert.strictEqual(verifiedUser.name, 'Pablo Developer');
    console.log('  ✓ Token verification passed (mock user profile resolved)');

    // 3. Connect Account & Persistence
    const connectRes = await githubService.connect('ghp_mock_token_for_testing_12345');
    assert.strictEqual(connectRes.success, true);
    assert.strictEqual(connectRes.user.login, 'pablo-developer');

    const connectedStatus = githubService.getStatus();
    assert.strictEqual(connectedStatus.connected, true);
    assert.ok(connectedStatus.tokenMasked.includes('••••'));
    console.log('  ✓ Account connection and token masking passed');

    // 4. List Repositories (Pagination & Search)
    const allRepos = await githubService.getRepositories({ perPage: 10 });
    assert.ok(allRepos.repos.length >= 3, 'Should list repositories');
    assert.strictEqual(allRepos.page, 1);

    const searchRes = await githubService.getRepositories({ search: 'voice' });
    assert.ok(searchRes.repos.some(r => r.name === 'ai-voice-agent'), 'Should find ai-voice-agent');
    console.log(`  ✓ Repositories listing and search filter passed (${allRepos.total} repos found)`);

    // 5. List Branches
    const branches = await githubService.getBranches('pablo-developer', 'culkibo-frontend');
    assert.ok(branches.length >= 2, 'Should list branches');
    const mainBranch = branches.find(b => b.name === 'main');
    assert.ok(mainBranch, 'Main branch should exist');
    console.log(`  ✓ Branch listing passed (${branches.map(b => b.name).join(', ')})`);

    // 6. Stack Auto-Detection
    // React / Vite
    const reactDetect = await githubService.autoDetectRepo('pablo-developer', 'culkibo-frontend', 'main');
    assert.strictEqual(reactDetect.detected, true);
    assert.strictEqual(reactDetect.framework, 'React (Vite)');
    assert.strictEqual(reactDetect.port, 5173);
    assert.strictEqual(reactDetect.buildCommand, 'npm run build');

    // Python FastAPI
    const pythonDetect = await githubService.autoDetectRepo('pablo-developer', 'ai-voice-agent', 'main');
    assert.strictEqual(pythonDetect.detected, true);
    assert.strictEqual(pythonDetect.framework, 'Python FastAPI');
    assert.strictEqual(pythonDetect.port, 8000);

    // Dockerfile
    const dockerDetect = await githubService.autoDetectRepo('pablo-developer', 'docker-edge-proxy', 'master');
    assert.strictEqual(dockerDetect.detected, true);
    assert.strictEqual(dockerDetect.framework, 'Dockerfile');
    assert.strictEqual(dockerDetect.port, 8080);

    // Extended frameworks
    const composeDetect = await githubService.autoDetectRepo('pablo-developer', 'docker-compose-infra', 'main');
    assert.strictEqual(composeDetect.framework, 'Docker Compose');
    assert.strictEqual(composeDetect.port, 8080);

    const astroDetect = await githubService.autoDetectRepo('pablo-developer', 'astro-portal', 'main');
    assert.strictEqual(astroDetect.framework, 'Astro');
    assert.strictEqual(astroDetect.port, 4321);

    const svelteDetect = await githubService.autoDetectRepo('pablo-developer', 'svelte-dashboard', 'main');
    assert.strictEqual(svelteDetect.framework, 'SvelteKit');
    assert.strictEqual(svelteDetect.port, 5173);

    const rustDetect = await githubService.autoDetectRepo('pablo-developer', 'rust-cargo-api', 'main');
    assert.strictEqual(rustDetect.framework, 'Rust');
    assert.strictEqual(rustDetect.port, 8080);

    const djangoDetect = await githubService.autoDetectRepo('pablo-developer', 'django-crm', 'main');
    assert.strictEqual(djangoDetect.framework, 'Python Django');
    assert.strictEqual(djangoDetect.port, 8000);

    console.log('  ✓ Stack auto-detection passed (React, FastAPI, Dockerfile, Compose, Astro, Svelte, Rust, Django)');

    // 7. Webhook HMAC SHA-256 Signature Verification & Auto-Deploy
    const testSecret = 'secret_webhook_test_xyz_98765';
    const testProject = projectManager.create({
      name: 'GitHub Webhook Test Project',
      description: 'Proyecto de prueba para validar webhook de GitHub',
      gitRepo: 'https://github.com/pablo-developer/culkibo-frontend.git',
      gitBranch: 'main',
      webhookSecret: testSecret,
      autoDeploy: true,
      icon: '⚡'
    });

    assert.ok(testProject.id, 'Test project created');
    assert.strictEqual(testProject.webhookSecret, testSecret);

    // Helper to simulate request to router
    const simulateWebhook = (payload, headers = {}, query = {}) => {
      return new Promise((resolve) => {
        const rawBody = Buffer.from(JSON.stringify(payload));
        const req = {
          headers: {
            'content-type': 'application/json',
            ...headers
          },
          body: payload,
          rawBody,
          query,
          url: '/webhooks/github',
          method: 'POST'
        };

        const res = {
          statusCode: 200,
          headersSent: false,
          status(code) {
            this.statusCode = code;
            return this;
          },
          json(data) {
            resolve({ statusCode: this.statusCode, data });
          },
          send(data) {
            resolve({ statusCode: this.statusCode, data });
          }
        };

        // Find webhook handler in apiRouter
        const routeLayer = apiRouter.stack.find(l => l.route && l.route.path === '/webhooks/github');
        assert.ok(routeLayer, 'Route /webhooks/github must exist in apiRouter');
        routeLayer.route.stack[0].handle(req, res, () => {
          resolve({ statusCode: 404, data: null });
        });
      });
    };

    // 7a. Reject missing signature when secret is configured
    const noSigRes = await simulateWebhook(
      { ping: true },
      { 'x-github-event': 'ping' },
      { projectId: testProject.id }
    );
    assert.strictEqual(noSigRes.statusCode, 401, 'Should reject missing signature');
    console.log('  ✓ Webhook HMAC rejection on missing signature passed');

    // 7b. Reject invalid signature
    const badSigRes = await simulateWebhook(
      { ping: true },
      {
        'x-github-event': 'ping',
        'x-hub-signature-256': 'sha256=0000000000000000000000000000000000000000000000000000000000000000'
      },
      { projectId: testProject.id }
    );
    assert.strictEqual(badSigRes.statusCode, 401, 'Should reject invalid signature');
    console.log('  ✓ Webhook HMAC rejection on invalid signature passed');

    // 7c. Accept valid signature for 'ping' event
    const pingPayload = { zen: 'Mind your words, they are important.', hook_id: 12345 };
    const pingRaw = Buffer.from(JSON.stringify(pingPayload));
    const validPingSig = 'sha256=' + crypto.createHmac('sha256', testSecret).update(pingRaw).digest('hex');

    const pingRes = await simulateWebhook(
      pingPayload,
      {
        'x-github-event': 'ping',
        'x-hub-signature-256': validPingSig
      },
      { projectId: testProject.id }
    );
    assert.strictEqual(pingRes.statusCode, 200);
    assert.strictEqual(pingRes.data.success, true);
    console.log('  ✓ Webhook Ping event handshake passed');

    // 7c-1. Uppercase signature acceptance (case-insensitivity)
    const upperSigRes = await simulateWebhook(
      pingPayload,
      {
        'x-github-event': 'ping',
        'x-hub-signature-256': validPingSig.toUpperCase()
      },
      { projectId: testProject.id }
    );
    assert.strictEqual(upperSigRes.statusCode, 200, 'Uppercase hex signature should be accepted');
    console.log('  ✓ Webhook HMAC case-insensitive signature validation passed');

    // 7c-2. Reject non-existent projectId with 404
    const unknownProjRes = await simulateWebhook(
      pingPayload,
      {
        'x-github-event': 'ping',
        'x-hub-signature-256': validPingSig
      },
      { projectId: 'proj_nonexistent_99999' }
    );
    assert.strictEqual(unknownProjRes.statusCode, 404, 'Should return 404 for unknown projectId');
    console.log('  ✓ Webhook rejection on unknown projectId (404) passed');

    // 7d. Push to non-configured branch (ignored)
    const otherBranchPayload = {
      ref: 'refs/heads/feature-login',
      repository: {
        full_name: 'pablo-developer/culkibo-frontend',
        clone_url: 'https://github.com/pablo-developer/culkibo-frontend.git'
      },
      head_commit: {
        id: '998877665544',
        message: 'feat: add login screen',
        author: { name: 'Pablo' }
      }
    };
    const otherBranchRaw = Buffer.from(JSON.stringify(otherBranchPayload));
    const otherBranchSig = 'sha256=' + crypto.createHmac('sha256', testSecret).update(otherBranchRaw).digest('hex');

    const otherBranchRes = await simulateWebhook(
      otherBranchPayload,
      {
        'x-github-event': 'push',
        'x-hub-signature-256': otherBranchSig
      },
      { projectId: testProject.id }
    );
    assert.strictEqual(otherBranchRes.statusCode, 200);
    assert.strictEqual(otherBranchRes.data.deployed, false, 'Push to different branch should not deploy');
    console.log('  ✓ Webhook ignores pushes to unmonitored branches');

    // 7e. Push to configured branch (triggers automatic deployment)
    const validPushPayload = {
      ref: 'refs/heads/main',
      after: 'e5f6a7b8c9d0',
      repository: {
        full_name: 'pablo-developer/culkibo-frontend',
        clone_url: 'https://github.com/pablo-developer/culkibo-frontend.git'
      },
      head_commit: {
        id: 'e5f6a7b8c9d0112233',
        message: 'feat: instant hot reload sub-35ms live',
        author: { name: 'Pablo Dev' }
      },
      commits: [
        { id: 'e5f6a7b8c9d0112233', message: 'feat: instant hot reload sub-35ms live' }
      ]
    };
    const validPushRaw = Buffer.from(JSON.stringify(validPushPayload));
    const validPushSig = 'sha256=' + crypto.createHmac('sha256', testSecret).update(validPushRaw).digest('hex');

    // Attach event listener to verify real-time WebSocket broadcast emission
    let deployEmitted = null;
    const deployHandler = (data) => { deployEmitted = data; };
    containerOrchestrator.once('github_deploy', deployHandler);

    const pushRes = await simulateWebhook(
      validPushPayload,
      {
        'x-github-event': 'push',
        'x-hub-signature-256': validPushSig
      },
      { projectId: testProject.id }
    );
    assert.strictEqual(pushRes.statusCode, 200);
    assert.strictEqual(pushRes.data.success, true);
    assert.strictEqual(pushRes.data.deployed, true);
    assert.strictEqual(pushRes.data.commit, 'e5f6a7b');

    // Verify WebSocket deploy event was emitted
    assert.ok(deployEmitted, 'github_deploy event should be emitted');
    assert.strictEqual(deployEmitted.projectId, testProject.id);
    assert.strictEqual(deployEmitted.commit, 'e5f6a7b');
    console.log('  ✓ Webhook automatic real-time deployment pipeline & WebSocket event passed');

    // Verify project state in projectManager
    const updatedProject = projectManager.getById(testProject.id);
    assert.ok(updatedProject.lastDeployedAt, 'Project lastDeployedAt should be updated');
    assert.strictEqual(updatedProject.lastCommit.sha, 'e5f6a7b');
    assert.strictEqual(updatedProject.lastCommit.author, 'Pablo Dev');

    // Verify orchestrator logs received deployment record
    const logs = containerOrchestrator.getLogs({ projectId: testProject.id, limit: 10 });
    assert.ok(logs.some(l => l.message.includes('Push recibido')), 'Orchestrator logs should record push');
    assert.ok(logs.some(l => l.message.includes('Despliegue completado')), 'Orchestrator logs should record deploy completion');

    // 7f. Disabled auto-deploy toggle prevents deployment
    projectManager.update(testProject.id, { autoDeploy: false });
    const disabledPushRes = await simulateWebhook(
      validPushPayload,
      {
        'x-github-event': 'push',
        'x-hub-signature-256': validPushSig
      },
      { projectId: testProject.id }
    );
    assert.strictEqual(disabledPushRes.statusCode, 200);
    assert.strictEqual(disabledPushRes.data.deployed, false, 'Disabled auto-deploy should skip deployment');
    console.log('  ✓ Disabled auto-deploy toggle correctly skips deployment');

    // Cleanup test project
    projectManager.delete(testProject.id);
    console.log('  ✓ Test project cleaned up successfully');

    // 7g. Substring repository matching protection test
    const projSecret = 'slug_collision_secret_123';
    const projectSub = projectManager.create({
      name: 'Frontend API Service',
      gitRepo: 'https://github.com/pablo-developer/test-unique-frontend-api.git',
      gitBranch: 'main',
      webhookSecret: projSecret,
      autoDeploy: true
    });
    const projectExact = projectManager.create({
      name: 'Frontend App',
      gitRepo: 'https://github.com/pablo-developer/test-unique-frontend.git',
      gitBranch: 'main',
      webhookSecret: projSecret,
      autoDeploy: true
    });

    const slugPushPayload = {
      ref: 'refs/heads/main',
      after: 'c0ffeec0ffee',
      repository: {
        full_name: 'pablo-developer/test-unique-frontend',
        clone_url: 'https://github.com/pablo-developer/test-unique-frontend.git'
      },
      head_commit: {
        id: 'c0ffeec0ffee',
        message: 'fix: prevent substring match bug',
        author: { name: 'Pablo' }
      }
    };
    const slugPushRaw = Buffer.from(JSON.stringify(slugPushPayload));
    const slugPushSig = 'sha256=' + crypto.createHmac('sha256', projSecret).update(slugPushRaw).digest('hex');

    // Send push without projectId query param (must resolve target project by slug accurately)
    const slugPushRes = await simulateWebhook(
      slugPushPayload,
      {
        'x-github-event': 'push',
        'x-hub-signature-256': slugPushSig
      }
    );
    assert.strictEqual(slugPushRes.statusCode, 200);
    assert.strictEqual(slugPushRes.data.deployed, true);
    assert.strictEqual(slugPushRes.data.projectId, projectExact.id, 'Must match exact repository slug and not substring project');
    projectManager.delete(projectSub.id);
    projectManager.delete(projectExact.id);
    await projectManager.flushToDisk();
    console.log('  ✓ Webhook exact slug matching prevents false-positive substring collision');

    // 8. Model Context Protocol (MCP) GitHub AI Agent Tools
    const mcpStatusRes = await mcpServer.executeTool('culkibo_github_status', {});
    assert.notStrictEqual(mcpStatusRes.isError, true);
    assert.ok(mcpStatusRes.content[0].text.includes('pablo-developer'));

    const mcpListRes = await mcpServer.executeTool('culkibo_github_list_repos', { search: 'voice' });
    assert.notStrictEqual(mcpListRes.isError, true);
    assert.ok(mcpListRes.content[0].text.includes('ai-voice-agent'));

    const mcpDetectRes = await mcpServer.executeTool('culkibo_github_auto_detect', {
      owner: 'pablo-developer',
      repo: 'culkibo-frontend',
      branch: 'main'
    });
    assert.notStrictEqual(mcpDetectRes.isError, true);
    assert.ok(mcpDetectRes.content[0].text.includes('React (Vite)'));

    const mcpCreateRes = await mcpServer.executeTool('culkibo_create_project_from_github', {
      owner: 'pablo-developer',
      repo: 'ai-voice-agent',
      branch: 'main',
      name: 'AI Voice Assistant Pod'
    });
    assert.notStrictEqual(mcpCreateRes.isError, true);
    const createdMcpData = JSON.parse(mcpCreateRes.content[0].text);
    assert.strictEqual(createdMcpData.project.name, 'AI Voice Assistant Pod');
    assert.strictEqual(createdMcpData.project.source, 'github');
    assert.strictEqual(createdMcpData.analysis.framework, 'Python FastAPI');

    // Cleanup MCP created project
    projectManager.delete(createdMcpData.project.id);
    await projectManager.flushToDisk();
    console.log('  ✓ MCP GitHub AI agent tools (status, list_repos, auto_detect, create_from_github) verified');

    console.log('✅ All GitHub & Webhook tests passed!\n');
  } finally {
    // Restore initial github config
    if (originalConfig && originalConfig.token) {
      githubService.saveConfig(originalConfig);
    }
  }
}

module.exports = testGithub;

if (require.main === module) {
  testGithub().catch(err => {
    console.error('❌ GitHub test failure:', err);
    process.exit(1);
  });
}
