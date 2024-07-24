/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ActionTypeModel as ConnectorTypeModel } from '@kbn/triggers-actions-ui-plugin/public';
import { SUB_ACTION } from '../../../common/inference/constants';
import { ChatCompleteParams } from '../../../common/inference/types';

export interface InferenceActionParams {
  subAction: SUB_ACTION.CHAT_COMPLETE | SUB_ACTION.TEST;
  subActionParams: ChatCompleteParams;
}

export interface Config {
  provider: string;
  taskType: string;
  providerConfig: Record<string, unknown>;
}

export interface Secrets {
  providerSecrets: Record<string, unknown>;
}

export type InferenceConnector = ConnectorTypeModel<Config, Secrets, InferenceActionParams>;
