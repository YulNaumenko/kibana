/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the "Elastic License
 * 2.0", the "GNU Affero General Public License v3.0 only", and the "Server Side
 * Public License v 1"; you may not use this file except in compliance with, at
 * your election, the "Elastic License 2.0", the "GNU Affero General Public
 * License v3.0 only", or the "Server Side Public License, v 1".
 */

import type { ElasticsearchClient } from '../elasticsearch_client';

/**
 * Retrieves the count of documents in a given index
 *
 * @param esClient An {@link ElasticsearchClient}
 * @param index index whose documents will be counted
 *
 * @returns the document count
 */
export const getIndexCount = async ({
  esClient,
  index,
}: {
  esClient: ElasticsearchClient;
  index: string;
}): Promise<number> => {
  const response = await esClient.count(
    {
      index,
    },
    { meta: true }
  );

  return response.body.count;
};
