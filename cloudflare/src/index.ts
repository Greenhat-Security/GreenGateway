import { Container, getContainer } from "@cloudflare/containers";
import type { StopParams } from "@cloudflare/containers";

import {
  buildGreenGatewayContainerEnv,
  CONTAINER_PORT,
  type GreenGatewayWorkerEnv,
} from "./config";

export interface Env extends GreenGatewayWorkerEnv {
  GREENGATEWAY_CONTAINER: DurableObjectNamespace<GreenGatewayContainer>;
}

export class GreenGatewayContainer extends Container<Env> {
  defaultPort = CONTAINER_PORT;
  sleepAfter = "10m";
  pingEndpoint = "localhost/health";

  constructor(ctx: DurableObjectState<{}>, env: Env) {
    super(ctx, env, {
      envVars: buildGreenGatewayContainerEnv(env),
    });
  }

  override onStart(): void {
    console.log("GreenGateway container started");
  }

  override onStop(params: StopParams): void {
    console.log("GreenGateway container stopped", params);
  }

  override onError(error: unknown): unknown {
    console.error("GreenGateway container error", error);
    throw error;
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    return getContainer(env.GREENGATEWAY_CONTAINER).fetch(request);
  },
} satisfies ExportedHandler<Env>;
