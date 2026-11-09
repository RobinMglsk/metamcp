import { DatabaseMcpServer, McpServer } from "@repo/zod-types";

import { redactSecrets } from "../../lib/redact";

export type Viewer = { userId: string; isAdmin: boolean };

export class McpServersSerializer {
  static serializeMcpServer(
    dbServer: DatabaseMcpServer,
    viewer?: Viewer,
  ): McpServer {
    const server = McpServersSerializer.toDto(dbServer);
    return viewer ? redactSecrets(server, dbServer.user_id, viewer) : server;
  }

  private static toDto(dbServer: DatabaseMcpServer): McpServer {
    return {
      uuid: dbServer.uuid,
      name: dbServer.name,
      description: dbServer.description,
      type: dbServer.type,
      command: dbServer.command,
      args: dbServer.args,
      env: dbServer.env,
      url: dbServer.url,
      error_status: dbServer.error_status,
      created_at: dbServer.created_at.toISOString(),
      bearerToken: dbServer.bearerToken,
      headers: dbServer.headers,
      forward_headers: dbServer.forward_headers,
      user_id: dbServer.user_id,
    };
  }

  static serializeMcpServerList(
    dbServers: DatabaseMcpServer[],
    viewer?: Viewer,
  ): McpServer[] {
    return dbServers.map((s) =>
      McpServersSerializer.serializeMcpServer(s, viewer),
    );
  }
}
