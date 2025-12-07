import { setTimeout as sleep } from "timers/promises";

// Configuration
const BASE_URL = process.env.BASE_URL || "http://localhost:3000";
const USERNAME = process.env.TEST_USERNAME || "testuser";
const PASSWORD = process.env.TEST_PASSWORD || "demo-password";

// Type definitions
interface HealthResponse {
  status: string;
  timestamp: string;
}

interface LoginResponse {
  token: string;
  username: string;
}

interface ErrorResponse {
  error: string;
}

interface MCPToolResponse {
  jsonrpc: string;
  id: number;
  result?: {
    content: Array<{
      type: string;
      text: string;
    }>;
    tools?: Array<{
      name: string;
      description: string;
      inputSchema: Record<string, any>;
    }>;
  };
  error?: {
    message: string;
    code?: number;
  };
}

// ANSI color codes for better output
const colors = {
  reset: "\x1b[0m",
  bright: "\x1b[1m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
};

// Helper functions
function log(message: string, color: string = colors.reset) {
  console.log(`${color}${message}${colors.reset}`);
}

function logSection(title: string) {
  console.log("\n" + "=".repeat(60));
  log(title, colors.bright + colors.cyan);
  console.log("=".repeat(60) + "\n");
}

function logTest(testNumber: number, description: string) {
  log(`\n${testNumber}. ${description}`, colors.bright + colors.yellow);
  log("-".repeat(60), colors.yellow);
}

function logSuccess(message: string) {
  log(`✓ ${message}`, colors.green);
}

function logError(message: string) {
  log(`✗ ${message}`, colors.red);
}

async function makeRequest(
  url: string,
  options: RequestInit = {}
): Promise<Response> {
  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options.headers,
      },
    });
    return response;
  } catch (error) {
    throw new Error(
      `Request failed: ${error instanceof Error ? error.message : String(error)}`
    );
  }
}

async function streamData(url: string, token: string): Promise<void> {
  const response = await fetch(url, {
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!response.ok) {
    throw new Error(`Stream failed: ${response.statusText}`);
  }

  const reader = response.body?.getReader();
  const decoder = new TextDecoder();

  if (!reader) {
    throw new Error("No response body");
  }

  let buffer = "";
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;

    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split("\n");
    buffer = lines.pop() || "";

    for (const line of lines) {
      if (line.startsWith("data: ")) {
        const data = line.slice(6);
        if (data === "[DONE]") {
          logSuccess("Stream completed");
        } else {
          try {
            const parsed = JSON.parse(data);
            log(`  Received: ${JSON.stringify(parsed)}`, colors.blue);
          } catch {
            log(`  Received: ${data}`, colors.blue);
          }
        }
      }
    }
  }
}

// Test suite
async function runTests() {
  logSection("MCP HTTP Server Test Suite");
  log(`Testing server at: ${BASE_URL}`, colors.cyan);

  let testsPassed = 0;
  let testsFailed = 0;
  let token = "";

  try {
    // Test 1: Health Check
    logTest(1, "Health Check (No Authentication)");
    try {
      const response = await makeRequest(`${BASE_URL}/health`);
      const data = (await response.json()) as HealthResponse;

      if (response.ok) {
        logSuccess("Health check passed");
        log(`  Status: ${data.status}`, colors.blue);
        log(`  Timestamp: ${data.timestamp}`, colors.blue);
        testsPassed++;
      } else {
        throw new Error(`Status: ${response.status}`);
      }
    } catch (error) {
      logError(
        `Health check failed: ${error instanceof Error ? error.message : String(error)}`
      );
      testsFailed++;
    }

    await sleep(500);

    // Test 2: Login - Success
    logTest(2, "Login with Valid Credentials");
    try {
      const response = await makeRequest(`${BASE_URL}/auth/login`, {
        method: "POST",
        body: JSON.stringify({
          username: USERNAME,
          password: PASSWORD,
        }),
      });

      if (response.ok) {
        const data = (await response.json()) as LoginResponse;
        token = data.token;
        logSuccess("Login successful");
        log(`  Username: ${data.username}`, colors.blue);
        log(`  Token: ${token.substring(0, 30)}...`, colors.blue);
        testsPassed++;
      } else {
        throw new Error(`Status: ${response.status}`);
      }
    } catch (error) {
      logError(
        `Login failed: ${error instanceof Error ? error.message : String(error)}`
      );
      testsFailed++;
      log("Cannot proceed with authenticated tests", colors.red);
      return;
    }

    await sleep(500);

    // Test 3: Login - Failure
    logTest(3, "Login with Invalid Credentials");
    try {
      const response = await makeRequest(`${BASE_URL}/auth/login`, {
        method: "POST",
        body: JSON.stringify({
          username: USERNAME,
          password: "wrong-password",
        }),
      });

      if (!response.ok) {
        const data = (await response.json()) as ErrorResponse;
        logSuccess("Correctly rejected invalid credentials");
        log(`  Error: ${data.error}`, colors.blue);
        testsPassed++;
      } else {
        throw new Error("Should have rejected invalid credentials");
      }
    } catch (error) {
      logError(
        `Test failed: ${error instanceof Error ? error.message : String(error)}`
      );
      testsFailed++;
    }

    await sleep(500);

    // Test 4: Unauthorized Access
    logTest(4, "Access Protected Endpoint Without Token");
    try {
      const response = await makeRequest(`${BASE_URL}/stream?count=1`);

      if (response.status === 401) {
        const data = (await response.json()) as ErrorResponse;
        logSuccess("Correctly rejected unauthorized access");
        log(`  Error: ${data.error}`, colors.blue);
        testsPassed++;
      } else {
        throw new Error("Should have rejected unauthorized access");
      }
    } catch (error) {
      logError(
        `Test failed: ${error instanceof Error ? error.message : String(error)}`
      );
      testsFailed++;
    }

    await sleep(500);

    // Test 5: Stream Data
    logTest(5, "Stream Data with Authentication");
    try {
      log("  Starting stream...", colors.blue);
      await streamData(`${BASE_URL}/stream?count=5`, token);
      testsPassed++;
    } catch (error) {
      logError(
        `Stream failed: ${error instanceof Error ? error.message : String(error)}`
      );
      testsFailed++;
    }

    await sleep(500);

    // Test 6: MCP Tool Call - stream_data
    logTest(6, "MCP Tool Call - stream_data");
    try {
      const response = await makeRequest(`${BASE_URL}/mcp`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: {
            name: "stream_data",
            arguments: {
              count: 3,
            },
          },
        }),
      });

      if (response.ok) {
        const data = (await response.json()) as MCPToolResponse;
        logSuccess("MCP tool call successful");
        log(`  Response:`, colors.blue);
        console.log(JSON.stringify(data, null, 2));
        testsPassed++;
      } else {
        throw new Error(`Status: ${response.status}`);
      }
    } catch (error) {
      logError(
        `MCP call failed: ${error instanceof Error ? error.message : String(error)}`
      );
      testsFailed++;
    }

    await sleep(500);

    // Test 7: MCP Tool Call - process_request
    logTest(7, "MCP Tool Call - process_request");
    try {
      const response = await makeRequest(`${BASE_URL}/mcp`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: {
            name: "process_request",
            arguments: {
              action: "test_action",
              data: "sample test data",
            },
          },
        }),
      });

      if (response.ok) {
        const data = (await response.json()) as MCPToolResponse;
        logSuccess("MCP tool call successful");
        log(`  Response:`, colors.blue);
        console.log(JSON.stringify(data, null, 2));
        testsPassed++;
      } else {
        throw new Error(`Status: ${response.status}`);
      }
    } catch (error) {
      logError(
        `MCP call failed: ${error instanceof Error ? error.message : String(error)}`
      );
      testsFailed++;
    }

    await sleep(500);

    // Test 8: MCP List Tools
    logTest(8, "MCP List Tools");
    try {
      const response = await makeRequest(`${BASE_URL}/mcp`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 3,
          method: "tools/list",
        }),
      });

      if (response.ok) {
        const data = (await response.json()) as MCPToolResponse;
        logSuccess("Listed available tools");
        log(`  Tools available:`, colors.blue);
        if (data.result?.tools) {
          data.result.tools.forEach((tool) => {
            log(`    - ${tool.name}: ${tool.description}`, colors.blue);
          });
        }
        testsPassed++;
      } else {
        throw new Error(`Status: ${response.status}`);
      }
    } catch (error) {
      logError(
        `List tools failed: ${error instanceof Error ? error.message : String(error)}`
      );
      testsFailed++;
    }

    await sleep(500);

    // Test 12: Unknown Tool
    logTest(12, "Call Unknown MCP Tool");
    try {
      const response = await makeRequest(`${BASE_URL}/stream?count=1`, {
        headers: {
          Authorization: "Bearer invalid-token-here",
        },
      });

      if (response.status === 403) {
        const data = (await response.json()) as ErrorResponse;
        logSuccess("Correctly rejected invalid token");
        log(`  Error: ${data.error}`, colors.blue);
        testsPassed++;
      } else {
        throw new Error("Should have rejected invalid token");
      }
    } catch (error) {
      logError(
        `Test failed: ${error instanceof Error ? error.message : String(error)}`
      );
      testsFailed++;
    }

    await sleep(500);

    // Test 10: Unknown Tool
    logTest(10, "Call Unknown MCP Tool");
    try {
      const response = await makeRequest(`${BASE_URL}/mcp`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 4,
          method: "tools/call",
          params: {
            name: "unknown_tool",
            arguments: {},
          },
        }),
      });

      const data = (await response.json()) as MCPToolResponse;
      if (data.error || !response.ok) {
        logSuccess("Correctly handled unknown tool");
        log(`  Error: ${data.error?.message || "Tool not found"}`, colors.blue);
        testsPassed++;
      } else {
        throw new Error("Should have failed for unknown tool");
      }
    } catch (error) {
      logError(
        `Test failed: ${error instanceof Error ? error.message : String(error)}`
      );
      testsFailed++;
    }
  } catch (error) {
    logError(
      `Fatal error: ${error instanceof Error ? error.message : String(error)}`
    );
  }

  // Summary
  logSection("Test Summary");
  log(`Total Tests: ${testsPassed + testsFailed}`, colors.bright);
  log(`Passed: ${testsPassed}`, colors.green);
  log(`Failed: ${testsFailed}`, testsFailed > 0 ? colors.red : colors.green);
  log(
    `Success Rate: ${((testsPassed / (testsPassed + testsFailed)) * 100).toFixed(1)}%`,
    colors.cyan
  );

  // Exit with appropriate code
  process.exit(testsFailed > 0 ? 1 : 0);
}

// Run tests
if (import.meta.url === `file://${process.argv[1]}`) {
  runTests().catch((error) => {
    logError(`Test suite failed: ${error.message}`);
    process.exit(1);
  });
}

export { runTests };