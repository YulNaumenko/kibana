/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { getFindRequest, requestMock } from '../../__mocks__/request';
import { ELASTIC_AI_ASSISTANT_CONVERSATIONS_URL_FIND_USER_CONVERSATIONS } from '@kbn/elastic-assistant-common';
import { serverMock } from '../../__mocks__/server';
import { requestContextMock } from '../../__mocks__/request_context';
import { getFindConversationsResultWithSingleHit } from '../../__mocks__/response';
import { findUserConversationsRoute } from './find_user_conversations_route';
import {
  getConversationMock,
  getQueryConversationParams,
} from '../../__mocks__/conversations_schema.mock';

describe('Find user conversations route', () => {
  let server: ReturnType<typeof serverMock.create>;
  let { clients, context } = requestContextMock.createTools();

  beforeEach(async () => {
    server = serverMock.create();
    ({ clients, context } = requestContextMock.createTools());

    clients.elasticAssistant.getAIAssistantConversationsDataClient.findConversations.mockResolvedValue(
      getFindConversationsResultWithSingleHit()
    );
    clients.elasticAssistant.getAIAssistantConversationsDataClient.getConversation.mockResolvedValue(
      getConversationMock(getQueryConversationParams())
    );

    findUserConversationsRoute(server.router);
  });

  describe('status codes', () => {
    test('returns 200', async () => {
      const response = await server.inject(
        getFindRequest(),
        requestContextMock.convertContext(context)
      );
      expect(response.status).toEqual(200);
    });

    test('catches error if search throws error', async () => {
      clients.elasticAssistant.getAIAssistantConversationsDataClient.findConversations.mockImplementation(
        async () => {
          throw new Error('Test error');
        }
      );
      const response = await server.inject(
        getFindRequest(),
        requestContextMock.convertContext(context)
      );
      expect(response.status).toEqual(500);
      expect(response.body).toEqual({
        message: 'Test error',
        status_code: 500,
      });
    });
  });

  describe('request validation', () => {
    test('allows optional query params', async () => {
      const request = requestMock.create({
        method: 'get',
        path: ELASTIC_AI_ASSISTANT_CONVERSATIONS_URL_FIND_USER_CONVERSATIONS,
        query: {
          page: 2,
          per_page: 20,
          sort_field: 'name',
          fields: ['field1', 'field2'],
        },
      });
      const result = server.validate(request);

      expect(result.ok).toHaveBeenCalled();
    });

    test('ignores unknown query params', async () => {
      const request = requestMock.create({
        method: 'get',
        path: ELASTIC_AI_ASSISTANT_CONVERSATIONS_URL_FIND_USER_CONVERSATIONS,
        query: {
          invalid_value: 'test 1',
        },
      });
      const result = server.validate(request);

      expect(result.ok).toHaveBeenCalled();
    });
  });
});
