/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { i18n } from '@kbn/i18n';

export const INFERENCE_CONNECTOR_TITLE = i18n.translate(
  'xpack.stackConnectors.components.inference.connectorTypeTitle',
  {
    defaultMessage: 'Inference Endpoint',
  }
);
export const INFERENCE_CONNECTOR_ID = '.inference';
export enum SUB_ACTION {
  TEST = 'test',
  CHAT_COMPLETE = 'chatComplete',
}

export const DEFAULT_PROVIDER = 'openai';
export const DEFAULT_TASK_TYPE = 'completion';
