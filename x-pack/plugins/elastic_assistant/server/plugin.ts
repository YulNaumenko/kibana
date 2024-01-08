/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import {
  PluginInitializerContext,
  CoreStart,
  Plugin,
  Logger,
  KibanaRequest,
  SavedObjectsClientContract,
  type AnalyticsServiceSetup,
} from '@kbn/core/server';
import { once } from 'lodash';

import { events } from './lib/telemetry/event_based_telemetry';
import {
  AssistantTool,
  ElasticAssistantPluginCoreSetupDependencies,
  ElasticAssistantPluginSetup,
  ElasticAssistantPluginSetupDependencies,
  ElasticAssistantPluginStart,
  ElasticAssistantPluginStartDependencies,
  ElasticAssistantRequestHandlerContext,
  GetElser,
} from './types';
import {
  deleteKnowledgeBaseRoute,
  getKnowledgeBaseStatusRoute,
  postActionsConnectorExecuteRoute,
  postEvaluateRoute,
  postKnowledgeBaseRoute,
} from './routes';
import { AIAssistantService } from './ai_assistant_service';
import { assistantPromptsType, assistantAnonimizationFieldsType } from './saved_object';
import {
  DataStreamAdapter,
  getDataStreamAdapter,
} from './ai_assistant_service/lib/create_datastream';
import { RequestContextFactory } from './routes/request_context_factory';
import { PLUGIN_ID } from '../common/constants';
import { registerConversationsRoutes } from './routes/register_routes';
import { appContextService } from './services/app_context';
import { appContextService, GetRegisteredTools } from './services/app_context';

interface CreateRouteHandlerContextParams {
  core: CoreSetup<ElasticAssistantPluginStart, unknown>;
  logger: Logger;
  getRegisteredTools: GetRegisteredTools;
  telemetry: AnalyticsServiceSetup;
}

export class ElasticAssistantPlugin
  implements
    Plugin<
      ElasticAssistantPluginSetup,
      ElasticAssistantPluginStart,
      ElasticAssistantPluginSetupDependencies,
      ElasticAssistantPluginStartDependencies
    >
{
  private readonly logger: Logger;
  private assistantService: AIAssistantService | undefined;
  private dataStreamAdapter: DataStreamAdapter;
  private readonly kibanaVersion: PluginInitializerContext['env']['packageInfo']['version'];

  constructor(initializerContext: PluginInitializerContext) {
    this.logger = initializerContext.logger.get();
    this.dataStreamAdapter = getDataStreamAdapter();
    this.kibanaVersion = initializerContext.env.packageInfo.version;
  }

  private createRouteHandlerContext = ({
    core,
    logger,
    getRegisteredTools,
    telemetry,
  }: CreateRouteHandlerContextParams): IContextProvider<
    ElasticAssistantRequestHandlerContext,
    typeof PLUGIN_ID
  > => {
    return async function elasticAssistantRouteHandlerContext(context, request) {
      const [_, pluginsStart] = await core.getStartServices();

      return {
        actions: pluginsStart.actions,
        getRegisteredTools,
        logger,
        telemetry,
      };
    };
  };

  public setup(
    core: ElasticAssistantPluginCoreSetupDependencies,
    plugins: ElasticAssistantPluginSetupDependencies
  ) {
    this.logger.debug('elasticAssistant: Setup');

    this.assistantService = new AIAssistantService({
      logger: this.logger.get('service'),
      taskManager: plugins.taskManager,
      kibanaVersion: this.kibanaVersion,
      dataStreamAdapter: this.dataStreamAdapter,
      elasticsearchClientPromise: core
        .getStartServices()
        .then(([{ elasticsearch }]) => elasticsearch.client.asInternalUser),
    });

    const requestContextFactory = new RequestContextFactory({
      logger: this.logger,
      core,
      plugins,
      kibanaVersion: this.kibanaVersion,
      assistantService: this.assistantService,
    });

    const router = core.http.createRouter<ElasticAssistantRequestHandlerContext>();
    core.http.registerRouteHandlerContext<ElasticAssistantRequestHandlerContext, typeof PLUGIN_ID>(
      PLUGIN_ID,
      (context, request) => requestContextFactory.create(context, request)
      this.createRouteHandlerContext({
        core: core as CoreSetup<ElasticAssistantPluginStart, unknown>,
        logger: this.logger,
        getRegisteredTools: (pluginName: string) => {
          return appContextService.getRegisteredTools(pluginName);
        },
        telemetry: core.analytics,
      })
    );
    events.forEach((eventConfig) => core.analytics.registerEventType(eventConfig));

    core.savedObjects.registerType(assistantPromptsType);
    core.savedObjects.registerType(assistantAnonimizationFieldsType);

    // this.assistantService registerKBTask

    const getElserId: GetElser = once(
      async (request: KibanaRequest, savedObjectsClient: SavedObjectsClientContract) => {
        return (await plugins.ml.trainedModelsProvider(request, savedObjectsClient).getELSER())
          .model_id;
      }
    );

    // Knowledge Base
    deleteKnowledgeBaseRoute(router);
    getKnowledgeBaseStatusRoute(router, getElserId);
    postKnowledgeBaseRoute(router, getElserId);
    // Actions Connector Execute (LLM Wrapper)
    postActionsConnectorExecuteRoute(router, getElserId);
    // Evaluate
    postEvaluateRoute(router, getElserId);
    // Conversations
    registerConversationsRoutes(router, this.logger);

    return {
      actions: plugins.actions,
      getRegisteredTools: (pluginName: string) => {
        return appContextService.getRegisteredTools(pluginName);
      },
    };
  }

  public start(core: CoreStart, plugins: ElasticAssistantPluginStartDependencies) {
    this.logger.debug('elasticAssistant: Started');
    appContextService.start({ logger: this.logger });

    return {
      /**
       * Actions plugin start contract
       */
      actions: plugins.actions,

      /**
       * Get the registered tools for a given plugin name.
       * @param pluginName
       */
      getRegisteredTools: (pluginName: string) => {
        return appContextService.getRegisteredTools(pluginName);
      },

      /**
       * Register tools to be used by the Elastic Assistant for a given plugin. Use the plugin name that
       * corresponds to your application as defined in the `x-kbn-context` header of requests made from your
       * application.
       *
       * @param pluginName
       * @param tools
       */
      registerTools: (pluginName: string, tools: AssistantTool[]) => {
        return appContextService.registerTools(pluginName, tools);
      },
    };
  }

  public stop() {
    appContextService.stop();
  }
}
