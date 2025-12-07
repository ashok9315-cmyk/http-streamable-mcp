import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import express, { Request, Response, NextFunction } from "express";
import { createServer } from "http";
import winston from "winston";
import jwt from "jsonwebtoken";
import crypto from "crypto";

// Configuration
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key-change-this";
const LOG_LEVEL = process.env.LOG_LEVEL || "info";
const OAUTH_CLIENT_ID = process.env.OAUTH_CLIENT_ID || "mcp-vscode-client";
const OAUTH_CLIENT_SECRET = process.env.OAUTH_CLIENT_SECRET || "mcp-secret-change-this";

// In-memory store for OAuth codes (use Redis in production)
const authorizationCodes = new Map<string, { 
  userId: string; 
  username: string; 
  expiresAt: number;
  codeChallenge?: string;
}>();
const refreshTokens = new Map<string, { 
  userId: string; 
  username: string; 
  expiresAt: number;
}>();

// Logger setup
const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
  ],
});

// Authentication middleware
interface AuthRequest extends Request {
  user?: { userId: string; username: string };
}

const authenticateToken = (
  req: AuthRequest,
  res: Response,
  next: NextFunction
) => {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    logger.warn("Authentication failed: No token provided");
    return res.status(401).json({ error: "Authentication required" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      logger.warn("Authentication failed: Invalid token", { error: err.message });
      return res.status(403).json({ error: "Invalid or expired token" });
    }
    req.user = user as { userId: string; username: string };
    logger.info("User authenticated", { userId: req.user.userId });
    next();
  });
};

// Helper function to generate random string
const generateRandomString = (length: number) => {
  return crypto.randomBytes(length).toString("hex");
};

// Create MCP Server
const mcpServer = new Server(
  {
    name: "streamable-mcp-server",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Define tools
mcpServer.setRequestHandler(ListToolsRequestSchema, async () => {
  logger.info("Listing available tools");
  return {
    tools: [
      {
        name: "stream_data",
        description: "Stream large amounts of data incrementally",
        inputSchema: {
          type: "object",
          properties: {
            count: {
              type: "number",
              description: "Number of items to stream",
            },
          },
          required: ["count"],
        },
      },
      {
        name: "process_request",
        description: "Process a request with logging",
        inputSchema: {
          type: "object",
          properties: {
            action: {
              type: "string",
              description: "Action to perform",
            },
            data: {
              type: "string",
              description: "Data to process",
            },
          },
          required: ["action"],
        },
      },
      {
        name: "calculator",
        description: "Perform mathematical calculations (add, subtract, multiply, divide)",
        inputSchema: {
          type: "object",
          properties: {
            operation: {
              type: "string",
              enum: ["add", "subtract", "multiply", "divide"],
              description: "Mathematical operation to perform",
            },
            a: {
              type: "number",
              description: "First number",
            },
            b: {
              type: "number",
              description: "Second number",
            },
          },
          required: ["operation", "a", "b"],
        },
      },
      {
        name: "get_cdd_alerts",
        description: "Tool to get CDD alerts for given user ID",
        inputSchema: {
          type: "object",
          properties: {
            id: {
              type: "string",
              description: "The ID of CDD user",
            },
          },
          required: ["id"],
        },
      },
    ],
  };
});

// Handle tool calls
mcpServer.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;
  logger.info("Tool called", { tool: name, arguments: args });

  try {
    switch (name) {
      case "stream_data": {
        const count = (args as { count: number }).count || 10;
        const items = Array.from({ length: count }, (_, i) => ({
          id: i + 1,
          data: `Item ${i + 1}`,
          timestamp: new Date().toISOString(),
        }));

        logger.info("Streaming data", { itemCount: count });
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(items, null, 2),
            },
          ],
        };
      }

      case "process_request": {
        const { action, data } = args as { action: string; data?: string };
        logger.info("Processing request", { action, hasData: !!data });

        const result = {
          action,
          processed: true,
          data: data || "No data provided",
          timestamp: new Date().toISOString(),
        };

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case "calculator": {
        const { operation, a, b } = args as {
          operation: "add" | "subtract" | "multiply" | "divide";
          a: number;
          b: number;
        };

        logger.info("Performing calculation", { operation, a, b });

        if (typeof a !== "number" || typeof b !== "number") {
          throw new Error("Both 'a' and 'b' must be numbers");
        }

        let calculationResult: number;
        let operationSymbol: string;

        switch (operation) {
          case "add":
            calculationResult = a + b;
            operationSymbol = "+";
            break;
          case "subtract":
            calculationResult = a - b;
            operationSymbol = "-";
            break;
          case "multiply":
            calculationResult = a * b;
            operationSymbol = "×";
            break;
          case "divide":
            if (b === 0) {
              throw new Error("Cannot divide by zero");
            }
            calculationResult = a / b;
            operationSymbol = "÷";
            break;
          default:
            throw new Error(
              `Invalid operation: ${operation}. Must be one of: add, subtract, multiply, divide`
            );
        }

        const response = {
          operation,
          operationSymbol,
          a,
          b,
          result: calculationResult,
          expression: `${a} ${operationSymbol} ${b} = ${calculationResult}`,
          timestamp: new Date().toISOString(),
        };

        logger.info("Calculation completed", {
          expression: response.expression,
          result: calculationResult,
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(response, null, 2),
            },
          ],
        };
      }

      case "get_cdd_alerts": {
        const { id } = args as { id: string };

        logger.info("Getting overdue CDD alerts", { userId: id });

        if (!id || typeof id !== "string") {
          throw new Error("User ID is required and must be a string");
        }

        try {
          const response = await fetch(
            `http://56e1097b-9ab1-4561-bdf0-155b380dbace.mock.pstmn.io/user/alertdetails/${id}`
          );
          const data = await response.json();

          if (!data || Object.keys(data).length === 0) {
            logger.warn("No alerts found", { userId: id });
            return {
              content: [
                {
                  type: "text",
                  text: `ID ${id} not found.`,
                },
              ],
            };
          }

          logger.info("Overdue CDD alerts retrieved", { userId: id });

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(data, null, 2),
              },
            ],
          };
        } catch (error) {
          logger.error("Error fetching CDD alerts", {
            userId: id,
            error: error instanceof Error ? error.message : String(error),
          });
          throw new Error(
            `Failed to fetch alerts for ID ${id}: ${error instanceof Error ? error.message : String(error)}`
          );
        }
      }

      default:
        logger.error("Unknown tool called", { tool: name });
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    logger.error("Error executing tool", {
      tool: name,
      error: error instanceof Error ? error.message : String(error),
    });
    throw error;
  }
});

// Express app setup
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS for development
app.use((req: Request, res: Response, next: NextFunction) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, Authorization");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

// Request logging middleware
app.use((req: Request, res: Response, next: NextFunction) => {
  logger.info("Incoming request", {
    method: req.method,
    path: req.path,
    ip: req.ip,
  });
  next();
});

// OAuth2 Authorization endpoint
app.get("/oauth/authorize", (req: Request, res: Response) => {
  const { client_id, redirect_uri, state, code_challenge, code_challenge_method } = req.query;

  logger.info("OAuth authorization request", { client_id, redirect_uri });

  // Validate client_id
  if (client_id !== OAUTH_CLIENT_ID) {
    return res.status(400).json({ error: "invalid_client" });
  }

  // Generate authorization code
  const code = generateRandomString(32);
  authorizationCodes.set(code, {
    userId: "user-" + generateRandomString(8),
    username: "oauth-user",
    expiresAt: Date.now() + 600000, // 10 minutes
    codeChallenge: code_challenge as string,
  });

  logger.info("Authorization code generated", { code });

  // Redirect back to client with code
  const redirectUrl = `${redirect_uri}?code=${code}&state=${state}`;
  res.redirect(redirectUrl);
});

// OAuth2 Token endpoint
app.post("/oauth/token", (req: Request, res: Response) => {
  const { grant_type, code, client_id, client_secret, refresh_token, code_verifier } = req.body;

  logger.info("OAuth token request", { grant_type, client_id });

  // Validate client credentials
  if (client_id !== OAUTH_CLIENT_ID || client_secret !== OAUTH_CLIENT_SECRET) {
    return res.status(401).json({ error: "invalid_client" });
  }

  if (grant_type === "authorization_code") {
    // Exchange authorization code for tokens
    const authData = authorizationCodes.get(code);
    
    if (!authData || authData.expiresAt < Date.now()) {
      return res.status(400).json({ error: "invalid_grant" });
    }

    // Verify PKCE if code_challenge was provided
    if (authData.codeChallenge && code_verifier) {
      const hash = crypto.createHash("sha256").update(code_verifier).digest("base64url");
      if (hash !== authData.codeChallenge) {
        return res.status(400).json({ error: "invalid_grant" });
      }
    }

    authorizationCodes.delete(code);

    // Generate tokens
    const accessToken = jwt.sign(
      { userId: authData.userId, username: authData.username },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    const refreshTokenValue = generateRandomString(32);
    refreshTokens.set(refreshTokenValue, {
      userId: authData.userId,
      username: authData.username,
      expiresAt: Date.now() + 2592000000, // 30 days
    });

    logger.info("Tokens generated", { userId: authData.userId });

    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
      refresh_token: refreshTokenValue,
    });
  } else if (grant_type === "refresh_token") {
    // Refresh access token
    const tokenData = refreshTokens.get(refresh_token);
    
    if (!tokenData || tokenData.expiresAt < Date.now()) {
      return res.status(400).json({ error: "invalid_grant" });
    }

    const accessToken = jwt.sign(
      { userId: tokenData.userId, username: tokenData.username },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    logger.info("Token refreshed", { userId: tokenData.userId });

    return res.json({
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 3600,
    });
  }

  res.status(400).json({ error: "unsupported_grant_type" });
});

// Simple login endpoint (for testing)
app.post("/auth/login", (req: Request, res: Response) => {
  const { username, password } = req.body;

  if (username && password === "demo-password") {
    const token = jwt.sign(
      { userId: Math.random().toString(36), username },
      JWT_SECRET,
      { expiresIn: "24h" }
    );

    logger.info("User logged in", { username });
    return res.json({ token, username });
  }

  logger.warn("Login failed", { username });
  res.status(401).json({ error: "Invalid credentials" });
});

// Streaming endpoint with authentication
app.get(
  "/stream",
  authenticateToken,
  async (req: AuthRequest, res: Response) => {
    logger.info("Starting stream", { userId: req.user?.userId });

    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");

    const count = parseInt(req.query.count as string) || 10;

    for (let i = 0; i < count; i++) {
      const data = {
        id: i + 1,
        message: `Streamed item ${i + 1}`,
        timestamp: new Date().toISOString(),
        user: req.user?.username,
      };

      res.write(`data: ${JSON.stringify(data)}\n\n`);
      logger.debug("Streamed data chunk", { id: i + 1 });

      await new Promise((resolve) => setTimeout(resolve, 500));
    }

    res.write("data: [DONE]\n\n");
    logger.info("Stream completed", { userId: req.user?.userId });
    res.end();
  }
);

// MCP endpoint with authentication
app.post("/mcp", authenticateToken, async (req: AuthRequest, res: Response) => {
  const { jsonrpc, id, method, params } = req.body;
  
  logger.info("MCP request received", {
    userId: req.user?.userId,
    method,
    id,
  });

  try {
    let result;

    switch (method) {
      case "initialize": {
        result = {
          protocolVersion: "2024-11-05",
          capabilities: {
            tools: {},
          },
          serverInfo: {
            name: "streamable-mcp-server",
            version: "1.0.0",
          },
        };
        break;
      }

      case "tools/list": {
        result = {
          tools: [
            {
              name: "stream_data",
              description: "Stream large amounts of data incrementally",
              inputSchema: {
                type: "object",
                properties: {
                  count: {
                    type: "number",
                    description: "Number of items to stream",
                  },
                },
                required: ["count"],
              },
            },
            {
              name: "process_request",
              description: "Process a request with logging",
              inputSchema: {
                type: "object",
                properties: {
                  action: {
                    type: "string",
                    description: "Action to perform",
                  },
                  data: {
                    type: "string",
                    description: "Data to process",
                  },
                },
                required: ["action"],
              },
            },
            {
              name: "calculator",
              description: "Perform mathematical calculations (add, subtract, multiply, divide)",
              inputSchema: {
                type: "object",
                properties: {
                  operation: {
                    type: "string",
                    enum: ["add", "subtract", "multiply", "divide"],
                    description: "Mathematical operation to perform",
                  },
                  a: {
                    type: "number",
                    description: "First number",
                  },
                  b: {
                    type: "number",
                    description: "Second number",
                  },
                },
                required: ["operation", "a", "b"],
              },
            },
            {
              name: "get_cdd_alerts",
              description: "Tool to get CDD alerts for given user ID",
              inputSchema: {
                type: "object",
                properties: {
                  id: {
                    type: "string",
                    description: "The ID of CDD user",
                  },
                },
                required: ["id"],
              },
            },
          ],
        };
        break;
      }

      case "tools/call": {
        if (!params || !params.name) {
          throw new Error("Tool name is required");
        }

        const { name, arguments: args } = params;
        logger.info("Executing tool", { tool: name, arguments: args });

        switch (name) {
          case "stream_data": {
            const count = (args as { count: number }).count || 10;
            const items = Array.from({ length: count }, (_, i) => ({
              id: i + 1,
              data: `Item ${i + 1}`,
              timestamp: new Date().toISOString(),
            }));

            result = {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(items, null, 2),
                },
              ],
            };
            break;
          }

          case "process_request": {
            const { action, data } = args as { action: string; data?: string };
            logger.info("Processing request", { action, hasData: !!data });

            const processResult = {
              action,
              processed: true,
              data: data || "No data provided",
              timestamp: new Date().toISOString(),
            };

            result = {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(processResult, null, 2),
                },
              ],
            };
            break;
          }

          case "calculator": {
            const { operation, a, b } = args as {
              operation: "add" | "subtract" | "multiply" | "divide";
              a: number;
              b: number;
            };

            logger.info("Performing calculation", { operation, a, b });

            if (typeof a !== "number" || typeof b !== "number") {
              throw new Error("Both 'a' and 'b' must be numbers");
            }

            let calculationResult: number;
            let operationSymbol: string;

            switch (operation) {
              case "add":
                calculationResult = a + b;
                operationSymbol = "+";
                break;
              case "subtract":
                calculationResult = a - b;
                operationSymbol = "-";
                break;
              case "multiply":
                calculationResult = a * b;
                operationSymbol = "×";
                break;
              case "divide":
                if (b === 0) {
                  throw new Error("Cannot divide by zero");
                }
                calculationResult = a / b;
                operationSymbol = "÷";
                break;
              default:
                throw new Error(`Invalid operation: ${operation}`);
            }

            const response = {
              operation,
              operationSymbol,
              a,
              b,
              result: calculationResult,
              expression: `${a} ${operationSymbol} ${b} = ${calculationResult}`,
              timestamp: new Date().toISOString(),
            };

            logger.info("Calculation completed", {
              expression: response.expression,
              result: calculationResult,
            });

            result = {
              content: [
                {
                  type: "text",
                  text: JSON.stringify(response, null, 2),
                },
              ],
            };
            break;
          }

          case "get_cdd_alerts": {
            const { id } = args as { id: string };

            logger.info("Getting overdue CDD alerts", { userId: id });

            if (!id || typeof id !== "string") {
              throw new Error("User ID is required and must be a string");
            }

            try {
              const response = await fetch(
                `http://56e1097b-9ab1-4561-bdf0-155b380dbace.mock.pstmn.io/user/alertdetails/${id}`
              );
              const data = await response.json();

              if (!data || Object.keys(data).length === 0) {
                logger.warn("No alerts found", { userId: id });
                result = {
                  content: [
                    {
                      type: "text",
                      text: `ID ${id} not found.`,
                    },
                  ],
                };
                break;
              }

              logger.info("Overdue CDD alerts retrieved", { userId: id });

              result = {
                content: [
                  {
                    type: "text",
                    text: JSON.stringify(data, null, 2),
                  },
                ],
              };
            } catch (error) {
              logger.error("Error fetching CDD alerts", {
                userId: id,
                error: error instanceof Error ? error.message : String(error),
              });
              throw new Error(
                `Failed to fetch alerts for ID ${id}: ${error instanceof Error ? error.message : String(error)}`
              );
            }
            break;
          }

          default:
            throw new Error(`Unknown tool: ${name}`);
        }
        break;
      }

      default:
        throw new Error(`Unsupported method: ${method}`);
    }

    res.json({
      jsonrpc: "2.0",
      id,
      result,
    });

    logger.info("MCP request completed successfully", { method, id });
  } catch (error) {
    logger.error("MCP request failed", {
      error: error instanceof Error ? error.message : String(error),
      method,
      id,
    });

    res.json({
      jsonrpc: "2.0",
      id,
      error: {
        code: -32603,
        message: error instanceof Error ? error.message : String(error),
      },
    });
  }
});

// Health check endpoint (no auth required)
app.get("/health", (req: Request, res: Response) => {
  res.json({ status: "healthy", timestamp: new Date().toISOString() });
});

// OAuth configuration endpoint (for VS Code)
app.get("/.well-known/oauth-authorization-server", (req: Request, res: Response) => {
  const baseUrl = `http://localhost:${PORT}`;
  res.json({
    issuer: baseUrl,
    authorization_endpoint: `${baseUrl}/oauth/authorize`,
    token_endpoint: `${baseUrl}/oauth/token`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
  });
});

// Error handling middleware
app.use((err: Error, req: Request, res: Response, next: NextFunction) => {
  logger.error("Unhandled error", {
    error: err.message,
    stack: err.stack,
    path: req.path,
  });
  res.status(500).json({ error: "Internal server error" });
});

// Start HTTP server
const httpServer = createServer(app);

httpServer.listen(PORT, () => {
  logger.info(`MCP HTTP server started`, { port: PORT });
  logger.info("OAuth Client Credentials:", {
    clientId: OAUTH_CLIENT_ID,
    clientSecret: OAUTH_CLIENT_SECRET,
  });
  logger.info("Available endpoints:", {
    authorize: `http://localhost:${PORT}/oauth/authorize`,
    token: `http://localhost:${PORT}/oauth/token`,
    mcp: `http://localhost:${PORT}/mcp`,
    health: `http://localhost:${PORT}/health`,
  });
});

// Start MCP server on stdio (for local MCP clients)
async function main() {
  const transport = new StdioServerTransport();
  await mcpServer.connect(transport);
  logger.info("MCP server connected via stdio");
}

// Handle process termination
process.on("SIGINT", () => {
  logger.info("Shutting down server");
  httpServer.close(() => {
    logger.info("Server closed");
    process.exit(0);
  });
});

// Start stdio transport if not in HTTP-only mode
if (process.env.STDIO_ENABLED !== "false") {
  main().catch((error) => {
    logger.error("Fatal error", { error: error.message });
    process.exit(1);
  });
}
