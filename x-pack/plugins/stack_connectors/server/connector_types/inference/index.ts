/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { i18n } from '@kbn/i18n';
import {
  SubActionConnectorType,
  ValidatorType,
} from '@kbn/actions-plugin/server/sub_action_framework/types';
import {
  GenerativeAIForSearchPlaygroundConnectorFeatureId,
  GenerativeAIForSecurityConnectorFeatureId,
} from '@kbn/actions-plugin/common';
import { ValidatorServices } from '@kbn/actions-plugin/server/types';
import { GenerativeAIForObservabilityConnectorFeatureId } from '@kbn/actions-plugin/common/connector_feature_config';
import { InferenceTaskType } from '@elastic/elasticsearch/lib/api/types';
import {
  INFERENCE_CONNECTOR_TITLE,
  INFERENCE_CONNECTOR_ID,
  ServiceProviderKeys,
  SUB_ACTION,
} from '../../../common/inference/constants';
import { ConfigSchema, SecretsSchema } from '../../../common/inference/schema';
import { Config, Secrets } from '../../../common/inference/types';
import { InferenceConnector } from './inference';
import { unflattenObject } from '../lib/unflatten_object';

export const getConnectorType = (): SubActionConnectorType<Config, Secrets> => ({
  id: INFERENCE_CONNECTOR_ID,
  name: INFERENCE_CONNECTOR_TITLE,
  getService: (params) => new InferenceConnector(params),
  schema: {
    config: ConfigSchema,
    secrets: SecretsSchema,
  },
  validators: [{ type: ValidatorType.CONFIG, validator: configValidator }],
  supportedFeatureIds: [
    GenerativeAIForSecurityConnectorFeatureId,
    GenerativeAIForSearchPlaygroundConnectorFeatureId,
    GenerativeAIForObservabilityConnectorFeatureId,
  ],
  minimumLicenseRequired: 'enterprise' as const,
  preSaveEventHandler: async ({ config, secrets, logger, scopedClusterClient, isUpdate }) => {
    const esClient = scopedClusterClient?.asCurrentUser;
    try {
      const taskSettings = config?.taskTypeConfig
        ? {
            ...unflattenObject(config?.taskTypeConfig),
          }
        : {};
      const serviceSettings = {
        ...unflattenObject(config?.providerConfig ?? {}),
        ...unflattenObject(secrets?.providerSecrets ?? {}),
      };
      if (isUpdate && config && config.provider) {
        // TODO: replace, when update API for inference endpoint exists
        await esClient?.inference.delete({
          task_type: config.taskType as InferenceTaskType,
          inference_id: config.inferenceId,
        });
        logger.info(
          `Inference endpoint for task type "${config?.taskType}" and inference id ${config?.inferenceId} was successfuly deleted`
        );
      }
      await esClient?.inference.put({
        inference_id: config?.inferenceId ?? '',
        task_type: config?.taskType as InferenceTaskType,
        inference_config: {
          service: config!.provider,
          service_settings: serviceSettings,
          task_settings: taskSettings,
        },
      });
      logger.info(
        `Inference endpoint for task type "${config?.taskType}" and inference id ${
          config?.inferenceId
        } was successfuly ${isUpdate ? 'update' : 'create'}`
      );
    } catch (e) {
      logger.error(
        `Failed to ${isUpdate ? 'update' : 'create'} inference endpoint for task type "${
          config?.taskType
        }" and inference id ${config?.inferenceId}. Error: ${e.message}`
      );
      throw e;
    }
  },
  postDeleteEventHandler: async ({ config, logger, scopedClusterClient }) => {
    const esClient = scopedClusterClient?.asInternalUser;
    try {
      if (config) {
        await esClient?.inference.delete({
          task_type: config.taskType as InferenceTaskType,
          inference_id: config.inferenceId,
        });
      }
      logger.info(
        `Inference endpoint for task type "${config?.taskType}" and inference id ${config?.inferenceId} was successfuly deleted`
      );
    } catch (e) {
      logger.error(
        `Failed to delete inference endpoint for task type "${config?.taskType}" and inference id ${config?.inferenceId}. Error: ${e.message}`
      );
      throw e;
    }
  },
});

export const configValidator = (configObject: Config, validatorServices: ValidatorServices) => {
  try {
    const { provider, taskType } = configObject;
    if (!Object.keys(ServiceProviderKeys).includes(provider)) {
      throw new Error(
        `API Provider is not supported${
          provider && provider.length ? `: ${provider}` : ``
        } by Inference Endpoint.`
      );
    }

    if (!Object.keys(SUB_ACTION).includes(taskType.toUpperCase())) {
      throw new Error(
        `Task type is not supported${
          taskType && taskType.length ? `: ${taskType}` : ``
        } by Inference Endpoint.`
      );
    }
    return configObject;
  } catch (err) {
    throw new Error(
      i18n.translate('xpack.stackConnectors.inference.configurationErrorApiProvider', {
        defaultMessage: 'Error configuring Inference API action: {err}',
        values: {
          err: err.toString(),
        },
      })
    );
  }
};
