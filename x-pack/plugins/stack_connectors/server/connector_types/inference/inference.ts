/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ServiceParams, SubActionConnector } from '@kbn/actions-plugin/server';

import { PassThrough, Stream } from 'stream';
import { IncomingMessage } from 'http';

import { AxiosError } from 'axios';
import { InferenceInferenceRequest, InferenceTaskType } from '@elastic/elasticsearch/lib/api/types';
import {
  ChatCompleteParamsSchema,
  RerankParamsSchema,
  SparseEmbeddingParamsSchema,
  TextEmbeddingParamsSchema,
} from '../../../common/inference/schema';
import {
  Config,
  Secrets,
  ChatCompleteParams,
  ChatCompleteResponse,
  StreamingResponse,
  RerankParams,
  RerankResponse,
  SparseEmbeddingParams,
  SparseEmbeddingResponse,
  TextEmbeddingParams,
  TextEmbeddingResponse,
} from '../../../common/inference/types';
import { SUB_ACTION } from '../../../common/inference/constants';

export class InferenceConnector extends SubActionConnector<Config, Secrets> {
  // Not using Axios
  protected getResponseErrorMessage(error: AxiosError): string {
    throw new Error('Method not implemented.');
  }

  private inferenceId;
  private taskType;

  constructor(params: ServiceParams<Config, Secrets>) {
    super(params);

    this.provider = this.config.provider;
    this.taskType = this.config.taskType;
    this.inferenceId = this.config.inferenceId;
    this.logger = this.logger;
    this.connectorID = this.connector.id;
    this.connectorTokenClient = params.services.connectorTokenClient;

    this.registerSubActions();
  }

  private registerSubActions() {
    this.registerSubAction({
      name: SUB_ACTION.COMPLETION,
      method: 'performApiCompletion',
      schema: ChatCompleteParamsSchema,
    });

    this.registerSubAction({
      name: SUB_ACTION.RERANK,
      method: 'performApiRerank',
      schema: RerankParamsSchema,
    });

    this.registerSubAction({
      name: SUB_ACTION.SPARSE_EMBEDDING,
      method: 'performApiSparseEmbedding',
      schema: SparseEmbeddingParamsSchema,
    });

    this.registerSubAction({
      name: SUB_ACTION.TEXT_EMBEDDING,
      method: 'performApiTextEmbedding',
      schema: TextEmbeddingParamsSchema,
    });

    this.registerSubAction({
      name: SUB_ACTION.COMPLETION_STREAM,
      method: 'performApiCompletionStream',
      schema: ChatCompleteParamsSchema,
    });
  }

  /**
   * responsible for making a POST request to the Inference API chat completetion task endpoint and returning the response data
   * @param body The stringified request body to be sent in the POST request.
   */
  public async performApiCompletion({ input }: ChatCompleteParams): Promise<ChatCompleteResponse> {
    const response = await this.performInferenceApi(
      { inference_id: this.inferenceId, input, task_type: this.taskType as InferenceTaskType },
      false
    );
    // const usageMetadata = response?.data?.usageMetadata;
    return response as ChatCompleteResponse;
  }

  /**
   * responsible for making a POST request to the Inference API chat completetion task endpoint and returning the response data
   * @param body The stringified request body to be sent in the POST request.
   */
  public async performApiRerank({ input, query }: RerankParams): Promise<RerankResponse> {
    const response = await this.performInferenceApi(
      {
        query,
        inference_id: this.inferenceId,
        input,
        task_type: this.taskType as InferenceTaskType,
      },
      false
    );
    return response as RerankResponse;
  }

  /**
   * responsible for making a POST request to the Inference API chat completetion task endpoint and returning the response data
   * @param body The stringified request body to be sent in the POST request.
   */
  public async performApiSparseEmbedding({
    input,
  }: SparseEmbeddingParams): Promise<SparseEmbeddingResponse> {
    const response = await this.performInferenceApi(
      { inference_id: this.inferenceId, input, task_type: this.taskType as InferenceTaskType },
      false
    );
    return response as SparseEmbeddingResponse;
  }

  /**
   * responsible for making a POST request to the Inference API text embedding task endpoint and returning the response data
   * @param body The stringified request body to be sent in the POST request.
   */
  public async performApiTextEmbedding({
    input,
    inputType,
  }: TextEmbeddingParams): Promise<TextEmbeddingResponse> {
    const response = await this.performInferenceApi(
      {
        inference_id: this.inferenceId,
        input,
        task_type: this.taskType as InferenceTaskType,
        task_settings: {
          input_type: inputType,
        },
      },
      false
    );
    return response as TextEmbeddingResponse;
  }

  /**
   * responsible for making a POST request to the Inference API chat completetion task endpoint and returning the response data
   * @param body The stringified request body to be sent in the POST request.
   */
  private async performInferenceApi(
    params: InferenceInferenceRequest,
    asStream: boolean = false
  ): Promise<unknown> {
    try {
      const response = await this.esClient?.inference.inference(params, { asStream });
      this.logger.info(
        `Perform Inference endpoint for task type "${this.taskType}" and inference id ${this.inferenceId}`
      );
      // TODO: const usageMetadata = response?.data?.usageMetadata;
      return response;
    } catch (err) {
      this.logger.error(`error perform inference endpoint API: ${err}`);
      throw err;
    }
  }

  private async streamAPI({ input }: ChatCompleteParams): Promise<StreamingResponse> {
    const response = await this.performInferenceApi(
      { inference_id: this.inferenceId, input, task_type: this.taskType as InferenceTaskType },
      true
    );

    return (response as Stream).pipe(new PassThrough());
  }

  /**
   *  takes input. It calls the streamApi method to make a
   *  request to the Inference API with the message. It then returns a Transform stream
   *  that pipes the response from the API through the transformToString function,
   *  which parses the proprietary response into a string of the response text alone
   * @param input A message to be sent to the API
   */
  public async performApiCompletionStream({ input }: ChatCompleteParams): Promise<IncomingMessage> {
    const res = (await this.streamAPI({
      input,
    })) as unknown as IncomingMessage;
    return res;
  }
}
