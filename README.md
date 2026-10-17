# OneAIMemory MCP Server

Local stdio MCP server exposing 5 tools to AI clients. Holds the data key and decrypts in-process.

Includes `remote-mcp-server/` for hosted remote MCP.

## Setup

```bash
npm install
npm run build
ONECON_PASSPHRASE=... npm run start
```
