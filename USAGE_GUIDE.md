# MCP Server with HTTP Streaming - Usage Guide

## Setup

1. **Install dependencies**:
```bash
npm install
```

2. **Create environment file**:
```bash
cp .env.example .env
# Edit .env and change JWT_SECRET
```

3. **Run the server**:
```bash
# Development mode with auto-reload
npm run dev

# Production mode
npm run build
npm start
```

## Features

### 1. **Logging**
- Winston-based logging with multiple transports
- Console output (colorized)
- File logging (error.log and combined.log)
- Structured JSON logs
- Configurable log levels via LOG_LEVEL env var

### 2. **Authentication**
- JWT-based authentication
- Token expiration (24 hours)
- Protected endpoints require Bearer token
- Login endpoint to obtain tokens

### 3. **HTTP Streaming**
- Server-Sent Events (SSE) for real-time streaming
- Authentication required for streams
- Configurable stream count

### 4. **MCP Protocol Support**
- Standard MCP server implementation
- Dual transport: stdio and HTTP
- Tool-based architecture

## API Endpoints

### 1. Login (No Auth Required)
```bash
curl -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "demo-password"}'
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "username": "testuser"
}
```

### 2. Health Check (No Auth Required)
```bash
curl http://localhost:3000/health
```

### 3. Stream Data (Auth Required)
```bash
# First, login and get token
TOKEN=$(curl -s -X POST http://localhost:3000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "testuser", "password": "demo-password"}' | jq -r '.token')

# Then stream data
curl -N http://localhost:3000/stream?count=5 \
  -H "Authorization: Bearer $TOKEN"
```

### 4. MCP Tool Call (Auth Required)
```bash
curl -X POST http://localhost:3000/mcp \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
      "name": "stream_data",
      "arguments": {
        "count": 5
      }
    }
  }'
```

## Testing

### Run the TypeScript Test Suite

The project includes a comprehensive TypeScript test suite (`test.ts`) that tests all endpoints:

```bash
# Run tests (make sure server is running first)
npm test

# Or run with custom configuration
BASE_URL=http://localhost:3000 TEST_USERNAME=testuser TEST_PASSWORD=demo-password npm test
```

The test suite includes 10 tests covering:
1. Health check (no auth)
2. Login with valid credentials
3. Login with invalid credentials
4. Unauthorized access attempt
5. HTTP streaming with authentication
6. MCP tool call - stream_data
7. MCP tool call - process_request
8. MCP list tools
9. Invalid token handling
10. Unknown tool handling

### Test Output Example

```
============================================================
MCP HTTP Server Test Suite
============================================================

Testing server at: http://localhost:3000

1. Health Check (No Authentication)
------------------------------------------------------------
✓ Health check passed
  Status: healthy
  Timestamp: 2025-12-07T10:30:00.000Z

2. Login with Valid Credentials
------------------------------------------------------------
✓ Login successful
  Username: testuser
  Token: eyJhbGciOiJIUzI1NiIsInR5cCI...

...

============================================================
Test Summary
============================================================
Total Tests: 10
Passed: 10
Failed: 0
Success Rate: 100.0%
```

## Logging Examples

The server logs all important events:

```
info: MCP HTTP server started {"port":3000}
info: Incoming request {"method":"POST","path":"/auth/login","ip":"::1"}
info: User logged in {"username":"testuser"}
info: User authenticated {"userId":"abc123"}
info: Starting stream {"userId":"abc123"}
debug: Streamed data chunk {"id":1}
info: Stream completed {"userId":"abc123"}
```

## Environment Variables

- `PORT`: Server port (default: 3000)
- `JWT_SECRET`: Secret key for JWT signing (change in production!)
- `LOG_LEVEL`: Logging level (error, warn, info, debug)
- `STDIO_ENABLED`: Enable stdio transport for local MCP clients (default: true)

## Security Notes

⚠️ **Important for Production**:
1. Change `JWT_SECRET` to a strong random value
2. Implement proper user authentication (replace demo logic)
3. Use HTTPS in production
4. Add rate limiting
5. Implement token refresh mechanism
6. Store passwords securely (bcrypt)
7. Add CORS configuration if needed

## Extending the Server

### Add a New Tool

```typescript
// In ListToolsRequestSchema handler
{
  name: "your_tool",
  description: "Your tool description",
  inputSchema: {
    type: "object",
    properties: {
      param: { type: "string" }
    },
    required: ["param"]
  }
}

// In CallToolRequestSchema handler
case "your_tool": {
  const { param } = args as { param: string };
  logger.info("Your tool called", { param });
  return {
    content: [{
      type: "text",
      text: `Processed: ${param}`
    }]
  };
}
```

### Add Custom Middleware

```typescript
app.use((req, res, next) => {
  // Your middleware logic
  logger.info("Custom middleware executed");
  next();
});
```

## Troubleshooting

**Issue**: "Authentication required" error
- Solution: Ensure you're including the Bearer token in the Authorization header

**Issue**: Port already in use
- Solution: Change the PORT environment variable or kill the process using the port

**Issue**: Logs not appearing
- Solution: Check LOG_LEVEL setting, ensure write permissions for log files

**Issue**: Token expired
- Solution: Login again to get a new token (tokens expire after 24 hours)