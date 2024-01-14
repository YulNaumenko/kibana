/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0; you may not use this file except in compliance with the Elastic License
 * 2.0.
 */

import { ElasticsearchClient } from '@kbn/core/server';

import { ConversationResponse, UUID } from '../schemas/conversations/common_attributes.gen';
import { SearchEsConversationSchema } from './types';
import { transformESToConversations } from './transforms';

export const getLastConversation = async (
  esClient: ElasticsearchClient,
  conversationIndex: string,
  userId: UUID
): Promise<ConversationResponse> => {
  const response = await esClient.search<SearchEsConversationSchema>({
    body: {
      sort: {
        updated_at: {
          order: 'desc',
        },
      },
      query: {
        bool: {
          filter: [{ term: { 'user.id': userId } }],
          must_not: {
            term: { excludeFromLastConversationStorage: false },
          },
        },
      },
      size: 1,
    },
    _source: true,
    ignore_unavailable: true,
    index: conversationIndex,
    seq_no_primary_term: true,
  });
  const conversation = transformESToConversations(response);
  return conversation[0] ?? null;
};
