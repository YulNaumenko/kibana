/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ConnectorServerSideDefinition } from '@kbn/search-connectors';
import type { FleetStartContract, FleetSetupContract } from '@kbn/fleet-plugin/server';
import {
  TaskManagerSetupContract,
  TaskManagerStartContract,
} from '@kbn/task-manager-plugin/server';
import { SavedObjectsServiceSetup, SavedObjectsServiceStart } from '@kbn/core-saved-objects-server';
import { LicensingPluginStart } from '@kbn/licensing-plugin/server';
import { CloudSetup, CloudStart } from '@kbn/cloud-plugin/server';
import { IRouter, StartServicesAccessor, Logger } from '@kbn/core/server';
import { MlPluginSetup } from '@kbn/ml-plugin/server';
import { DataPluginStart } from '@kbn/data-plugin/server/plugin';
import { SpacesPluginStart } from '@kbn/spaces-plugin/server';
import { FeaturesPluginSetup } from '@kbn/features-plugin/server';

export interface SearchConnectorsPluginSetup {
  getConnectorTypes: () => ConnectorServerSideDefinition[];
}

export interface SearchConnectorsPluginStart {
  cloud?: CloudStart;
  data?: DataPluginStart;
  fleet?: FleetStartContract;
  spaces?: SpacesPluginStart;
  getConnectors: () => ConnectorServerSideDefinition[];
}

export interface SearchConnectorsPluginStartDependencies {
  fleet: FleetStartContract;
  taskManager: TaskManagerStartContract;
  soClient: SavedObjectsServiceStart;
  licensing: LicensingPluginStart;
}
export interface SearchConnectorsPluginSetupDependencies {
  features: FeaturesPluginSetup;
  fleet: FleetSetupContract;
  taskManager: TaskManagerSetupContract;
  soClient: SavedObjectsServiceSetup;
  cloud: CloudSetup;
  licensing?: LicensingPluginStart;
  log: Logger;
  ml?: MlPluginSetup;
  router: IRouter;
  getStartServices: StartServicesAccessor<SearchConnectorsPluginStart, unknown>;
}
